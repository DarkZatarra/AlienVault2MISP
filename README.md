# AlienVault2MISP
This should be a script which is able to get data from AlienVault and ingests it to a MISP server

To create the timestamp file run this command:

```date --date="1 days ago" "+%Y-%m-%dT%H:%M:%S.%N" > timestamp```


## Config

You have to create a `.env` file which contains the following environment variables:

```.env
OTX_KEY=<OTX KEY HERE>
MISP_KEY=<MISP KEY HERE>
```

Also, don't forget to:

```shell script
pip install -r requirements.txt
```