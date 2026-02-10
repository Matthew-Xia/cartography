import argparse
import getpass
import logging
import os
import sys
from typing import Optional

import cartography.config
import cartography.sync
import cartography.util


logger = logging.getLogger(__name__)


class CLI:
    """
    :type sync: cartography.sync.Sync
    :param sync: A sync task for the command line program to execute.
    :type prog: string
    :param prog: The name of the command line program. This will be displayed in usage and help output.
    """

    def __init__(
        self,
        sync: Optional[cartography.sync.Sync] = None,
        prog: Optional[str] = None,
    ):
        self.sync = sync if sync else cartography.sync.build_default_sync()
        self.prog = prog
        self.parser = self._build_parser()

    def _build_parser(self):
        """
        :rtype: argparse.ArgumentParser
        :return: A cartography argument parser. Calling parse_args on the argument parser will return an object which
            implements the cartography.config.Config interface.
        """
        parser = argparse.ArgumentParser(
            prog=self.prog,
            description=(
                "cartography consolidates infrastructure assets and the relationships between them in an intuitive "
                "graph view. This application can be used to pull configuration data from multiple sources, load it "
                "in to Neo4j, and run arbitrary enrichment and analysis on that data. Please make sure you have Neo4j "
                "running and have configured AWS credentials with the SecurityAudit IAM policy before getting started. "
                "Running cartography with no parameters will execute a simple sync against a Neo4j instance running "
                "locally. It will use your default AWS credentials and will not execute and post-sync analysis jobs. "
                "Please see the per-parameter documentation below for information on how to connect to different Neo4j "
                "instances, use auth when communicating with Neo4j, sync data from multiple AWS accounts, and execute "
                "arbitrary analysis jobs after the conclusion of the sync."
            ),
            epilog="For more documentation please visit: https://github.com/cartography-cncf/cartography",
        )
        parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Enable verbose logging for cartography.",
        )
        parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Restrict cartography logging to warnings and errors only.",
        )
        parser.add_argument(
            "--neo4j-uri",
            type=str,
            default="bolt://localhost:7687",
            help=(
                "A valid Neo4j URI to sync against. See "
                "https://neo4j.com/docs/browser-manual/current/operations/dbms-connection/#uri-scheme for complete "
                "documentation on the structure of a Neo4j URI."
            ),
        )
        parser.add_argument(
            "--neo4j-user",
            type=str,
            default=None,
            help="A username with which to authenticate to Neo4j.",
        )
        parser.add_argument(
            "--neo4j-password-env-var",
            type=str,
            default=None,
            help="The name of an environment variable containing a password with which to authenticate to Neo4j.",
        )
        parser.add_argument(
            "--neo4j-password-prompt",
            action="store_true",
            help=(
                "Present an interactive prompt for a password with which to authenticate to Neo4j. This parameter "
                "supersedes other methods of supplying a Neo4j password."
            ),
        )
        parser.add_argument(
            "--neo4j-max-connection-lifetime",
            type=int,
            default=3600,
            help=(
                "Time in seconds for the Neo4j driver to consider a TCP connection alive. cartography default = 3600, "
                "which is the same as the Neo4j driver default. See "
                "https://neo4j.com/docs/driver-manual/1.7/client-applications/#driver-config-connection-pool-management"
                "."
            ),
        )
        parser.add_argument(
            "--neo4j-database",
            type=str,
            default=None,
            help=(
                "The name of the database in Neo4j to connect to. If not specified, uses the config settings of your "
                "Neo4j database itself to infer which database is set to default. "
                "See https://neo4j.com/docs/api/python-driver/4.4/api.html#database."
            ),
        )
        parser.add_argument(
            "--selected-modules",
            type=str,
            default=None,
            help=(
                'Comma-separated list of cartography top-level modules to sync. Example 1: "aws,gcp" to run AWS and GCP'
                "modules. See the full list available in source code at cartography.sync. "
                "If not specified, cartography by default will run all modules available and log warnings when it "
                "does not find credentials configured for them. "
                # TODO remove this mention about the create-indexes module when everything is using auto-indexes.
                "We recommend that you always specify the `create-indexes` module first in this list. "
                "If you specify the `analysis` module, we recommend that you include it as the LAST item of this list, "
                "(because it does not make sense to perform analysis on an empty/out-of-date graph)."
            ),
        )
        # TODO add the below parameters to a 'sync' subparser
        parser.add_argument(
            "--update-tag",
            type=int,
            default=None,
            help=(
                "A unique tag to apply to all Neo4j nodes and relationships created or updated during the sync run. "
                "This tag is used by cleanup jobs to identify nodes and relationships that are stale and need to be "
                "removed from the graph. By default, cartography will use a UNIX timestamp as the update tag."
            ),
        )
        parser.add_argument(
            "--nist-cve-url",
            type=str,
            default="https://services.nvd.nist.gov/rest/json/cves/2.0/",
            help=(
                "The base url for the NIST CVE data. Default = https://services.nvd.nist.gov/rest/json/cves/2.0/"
            ),
        )
        parser.add_argument(
            "--cve-enabled",
            action="store_true",
            help=("If set, CVE data will be synced from NIST."),
        )
        parser.add_argument(
            "--cve-api-key-env-var",
            type=str,
            default=None,
            help=("If set, uses the provided NIST NVD API v2.0 key."),
        )

        return parser

    def main(self, argv: str) -> int:
        """
        Entrypoint for the command line interface.

        :type argv: string
        :param argv: The parameters supplied to the command line program.
        """
        # TODO support parameter lookup in environment variables if not present on command line
        config: argparse.Namespace = self.parser.parse_args(argv)
        # Logging config
        if config.verbose:
            logging.getLogger("cartography").setLevel(logging.DEBUG)
        elif config.quiet:
            logging.getLogger("cartography").setLevel(logging.WARNING)
        else:
            logging.getLogger("cartography").setLevel(logging.INFO)
        logger.debug("Launching cartography with CLI configuration: %r", vars(config))

        # Selected modules
        if config.selected_modules:
            self.sync = cartography.sync.build_sync(config.selected_modules)

        # CVE feed config
        if config.cve_api_key_env_var:
            logger.debug(
                f"Reading NVD CVE API key environment variable {config.cve_api_key_env_var}",
            )
            config.cve_api_key = os.environ.get(config.cve_api_key_env_var)
        else:
            config.cve_api_key = None

        
        # Run cartography
        try:
            return cartography.sync.run_with_config(self.sync, config)
        except KeyboardInterrupt:
            return cartography.util.STATUS_KEYBOARD_INTERRUPT


def main(argv=None):
    """
    Entrypoint for the default cartography command line interface.

    This entrypoint build and executed the default cartography sync. See cartography.sync.build_default_sync.

    :rtype: int
    :return: The return code.
    """
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("googleapiclient").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("azure.identity").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
        logging.WARNING
    )

    argv = argv if argv is not None else sys.argv[1:]
    sys.exit(CLI(prog="cartography").main(argv))
