# GT-CRIVO DefectDojo extensions

Our project has made three main extensions to DefectDojo.  A key requirement our extensions support is that they make *zero* changes to DefectDojo's models or database; this ensures that any deployment using our extensions can be trivially reverted to a vanilla DefectDojo deployment by just changing the codebase.

1. The ability to group `Findings` into `Problems`.  Our extension receives as input any mapping of `Findings` to `Problems`; one of which we have built using Artificial Intelligence to analyze the detection scripts used by scanning techniques.

2. The ability for analysts to specify the priority of a vulnerability (a `Vote`).  This is integrated with Dojo's interface, and the information used to train the vulnerability prioritization model developed in the project. `Vote`s are stored in a separate SQLite database.

3. Integration of complementary metadata which to aid analysts investigate and troubleshoot a `Finding`.  The metadata are downloaded directly from [authoritative](https://www.first.org/epss/) [sources](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and shown in Dojo's `Finding` view.  Some of the metadata we integrate [are also available as a paid feature in Dojo's Pro subscription](https://github.com/DefectDojo/django-DefectDojo/discussions/11796), which helps illustrate their usefulness.

> A `Finding` is DefectDojo's terminology for any result (or "finding") reported by any of the integrated tools.  A `Finding` is somewhat of a catch-all structure given the wide spectrum of tools supported by DefectDojo, whose results are all stored in the same `Finding` class.  In the context of our project, `Finding`s come from network vulnerability scanners like Nuclei, Nmap, and OpenVAS.

## Using Our Extensions

Using our extensions should be straightforward, but one thing is worth noting:  DefectDojo discards a lot of important information when importing OpenVAS reports; most crucial among these the list of CVEs related to a `Finding`.

As a result, any reports previously imported into Dojo's database prior to deploying our extensions will be missing this information and not have any metadata associated with them.

Any new XML reports imported after our extended Dojo version is deployed *will* store the necessary information to provide rich metadata about `Finding`s and their CVEs.

## Installation

Installation of our extensions follows the [normal installation procedure for DefectDojo](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md).  You should just follow the installation procedure on top of [our development branch](https://github.com/iago-r/django-DefectDojo/tree/crivo).  We frequently rebase our changes on top of Dojo's `master` branch to keep up to date with fixes and improvements on the platform, which also make it easy to check [the changes we have made to the code](https://github.com/DefectDojo/django-DefectDojo/compare/master...iago-r:django-DefectDojo:crivo).  The following will download the necessary metadata and launch our extended version of Dojo:

```bash
docker compose -f docker-compose.yml -f docker-compose-crivo-init.yml \
        up crivo-init
docker compose build
docker compose up
```

### Running Both Versions in Parallel

Our modified version has been tested to operate in parallel with and not impacting Dojo's upstream version.  To do this, one can generate alternate versions of the `nginx` and `uwsgi` containers, modifying the port and hostname used to communicate between the two.  This requires:

1. Changing the `published` port numbers in the `nginx` container;
2. Changing the `uwsgi` port and address used by `nginx` (defined in the `DD_UWSGI_HOST` and `DD_UWSGI_PORT` environment variables).
3. Change the endpoint that the `uwsgi` container binds to.  This is not defined in the Docker compose, but setting the `DD_UWSGI_ENDPOINT` environment variable works (e.g., to `"0.0.0.0:13031"`).

We have provided a `docker-compose-crivo.yml` that can be used to create and launch these additional containers together with Dojo's own container.  If your DefectDojo instance is already running (likely from another directory), and you just want to launch our additional containers, you can run:

```bash
docker compose -p $PROJECT \
        -f docker-compose.yml -f docker-compose-crivo-init.yml \
        up crivo-init
docker compose -p $PROJECT -f docker-compose.yml -f docker-compose-crivo.yml \
        up crivouwsgi crivonginx
```

Here, `$PROJECT` is the project name used by Docker Compose on your original deployment. This is usually the name of the directory where `docker compose` is initially run (e.g., `django-defectdojo`).  You can check the project name by running `docker ps` and check the prefix before Dojo's container names.  For example, if your containers are named `asdf-uwsgi-1`, then your `$PROJECT` is `asdf`.

## Configuration

The development branch is already preconfigured to run Dojo with the default configuration for our extensions.  Following Dojo's installation procedure on top of our branch should get you a working deployment with the extensions preconfigured.  The information below is provided as documentation.

We inject the necessary metadata inside Dojo's running container by mounting a Docker volume inside the container.  The volume configuration is inside Dojo's `docker-compose.yml` file, and mounts the `defectdojo_crivo` volume inside the container at `/app/crivo-metadata` inside the container.

The configuration parameters below are provided inside `crivo_settings.py`, which is imported by Dojo's (actually Django's) `settings.py` file.  The required files mentioned in the subsections below can be downloaded automatically by running the `crivo-init` container, which you can launch using:

```bash
docker compose -f docker-compose.yml -f docker-compose-crivo-init.yml \
    up crivo-init
```

The documentation below provides details on specific bits of configuration.

### `Problem` Mappings

`Finding` to `Problem` mappings should be provided as either an `https` or `file` URL in the `PROBLEM_MAPPINGS_JSON_URL` configuration variable. If this variable is not provided or set to `None`, the `Problem` tab will simply not show up in the interface, maintaining Dojo's default functionality.

The mapping of `Finding`s to `Problem`s generated in the project using Large Language Models (LLM) is available over `HTTPS` from a server at UFMG and can be configured as follows. Our mapping groups `Findings` from Nmap, OpenVAS, Nuclei, and Metasploit.

```python
PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"
```

A local `file` URL needs to point to where our metadata volume is mounted inside the container.  You can copy a file into the volume by using `docker cp` to copy it into the running container inside the `crivo-metadata` volume. The volume is mounted in the `uwsgi` container. You can check the container name by running `docker ps` and looking for the container that has the volume attached.

```python
docker cp <my_disambiguator.json> <uwsgi_container_name>:/app/crivo-metadata/
```

Another way to add your disambiguator, if you have permission, is to find the volume path on the host and place the file directly:

```python
docker volume inspect <crivo_volume_name>
```

Now you can just set the configuration variable for your disambiguator, if you have one, and rebuild the container. Like:

```python
PROBLEM_MAPPINGS_JSON_URL = "file:///app/crivo-metadata/<my_disambiguator.json>"
```

If configured with an URL, we will attempt to renew the disambiguator file daily at midnight.

If you want to refresh the problems map at any point in time, you can to remove the `problems` and `id_to_problem` keys from Redis, like this:

```python
docker exec -it <redis_container_name> redis-cli DEL problems id_to_problem
```

### `Vote` Database

The `Vote` database is totally separate from Dojo's PostgreSQL database.  We store analyst votes in a SQLite database that is stored in the metadata volume.  Only `file` URLs are supported:

```python
VOTE_DB_URL = "file:///app/crivo-metadata/vote-db.sqlite3"
```

> After we have data to train a new vulnerability prioritization model, it will be added to the metadata directory and a corresponding configuration entry will be added.

### CVE Metadata

The CVE metadata is also stored inside the `crivo-metadata` volume.  We currently support metadata to show the EPSS assigned to CVEs related to a vulnerability, downloaded directly from [FIRST](https://www.first.org/epss/); whether any CVE is in the [Known Exploited Vulnerabilities database](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); and a classification of impact of CVEs generated by the project using language models on the CVE description text.  These are configured with the following, these files are downloaded by the `crivo-init` container, processed into a Pickle file, which is then loaded by DefectDojo using our `DataStore` class.

## Database Backup

One can create a dump of the PostgreSQL database used by Dojo as a backup.  However, it is important to write down the version of DefectDojo in use (e.g., the commit hash or release tag) when the dump is collected such that the exact same version can be used when restoring the database.  This will ensure that all migrations are applied to the database.  The following is an example of how one can make a backup of the database and restore into a new Dojo instance:

```bash
docker compose exec postgres pg_dumpall -U defectdojo -f /dump.sql
docker compose cp postgres:/dump.sql ./dump.sql
# dump.sql is not a dump of the current Dojo deployment

# we will load the database in the new deployment *before* initializing
# the database to avoid conflicts (as the backup will try to recreate
# relationships and tables).
docmer compose -p dojo2 up postgres
docker compose -p dojo2 cp ./dump.sql postgres:/dump.sql
docker compose -p dojo2 exec postgres psql -U defectdojo -f /dump.sql

# now simply stop the postgres instance (ctrl-c on it), and restart dojo:
docker compose -p dojo2 up
```

Note that `-p dojo2` is optional, it is just one way of creating a *different* deployment (with new containers, database, and volume) from the existing one.
