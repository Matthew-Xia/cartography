![Cartography](docs/root/images/logo-horizontal.png)



Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a [Postgres](https://www.postgresql.org/) database.

## Why Cartography?
Cartography aims to enable a broad set of exploration and automation scenarios. It is particularly good at exposing otherwise hidden dependency relationships between your service's assets so that you may validate assumptions about security risks.

Service owners can generate asset reports, Red Teamers can discover attack paths, and Blue Teamers can identify areas for security improvement. All can benefit from using the graph for manual exploration through a web frontend interface, or in an automated fashion by calling the APIs.

Cartography is not the only [security](https://github.com/dowjones/hammer) [graph](https://github.com/BloodHoundAD/BloodHound) [tool](https://github.com/Netflix/security_monkey) [out](https://github.com/vysecurity/ANGRYPUPPY) [there](https://github.com/duo-labs/cloudmapper), but it differentiates itself by being fully-featured yet generic and [extensible](https://cartography-cncf.github.io/cartography/dev/writing-analysis-jobs.html) enough to help make anyone better understand their risk exposure, regardless of what platforms they use. Rather than being focused on one core scenario or attack vector like the other linked tools, Cartography focuses on flexibility and exploration.

You can learn more about the story behind Cartography in our [presentation at BSidesSF 2019](https://www.youtube.com/watch?v=ZukUmZSKSek).


## Supported platforms
- [NIST CVE](https://cartography-cncf.github.io/cartography/modules/cve/index.html) - Common Vulnerabilities and Exposures (CVE) data from NIST database

## Setup
Clone the repository and install dependencies
```bash
git clone https://github.com/Matthew-Xia/cartography
```
```bash
pip install .
```

## Initialize Postgres database
Install postgres and follow the [instructions] (https://www.postgresql.org/docs/current/tutorial-start.html) to initialize the database.

Make sure the server is being run on localhost:5432

## Usage
Request a NIST CVE API key through [this link](https://nvd.nist.gov/developers/request-an-api-key)

```bash
python3 cartography --cve-enabled --cve-api-key-env-var=<CVE_API_KEY>
```

### Using Puppygraph
Follow the instructions [here](https://docs.puppygraph.com/getting-started/querying-postgresql-data-as-a-graph/) on a demo for how to connect Puppygraph to a Postgres database.

Through Puppygraph, you can query the graph using [openCypher](https://opencypher.org/) or [Gremlin](https://tinkerpop.apache.org/gremlin.html)

### Building applications around Cartography
Direct queries are already very useful as a sort of "swiss army knife" for security data problems, but you can also build applications and data pipelines around Cartography. View this doc on [applications](https://cartography-cncf.github.io/cartography/usage/applications.html).
