# AlienVault2MISP
This should be a script which is able to get data from AlienVault and ingests it to a MISP server

## Config

You have to create a `.env` file which contains the following environment variables:

```.env
OTX_KEY=<OTX KEY HERE>
MISP_URL=<MISP URL HERE>
MISP_KEY=<MISP KEY HERE>
```

Also, don't forget to:

```shell script
pip install -r requirements.txt
```
