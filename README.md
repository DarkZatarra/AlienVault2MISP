# AlienVault2MISP
This should be a script which is able to get data from AlienVault and ingests it to a MISP server

## Config

```
This is special setting for AWS
```

Also, don't forget to:

```shell script
pip install -r requirements.txt
```

## Do we need this thing?

```markdown
The `getall()` method downloads all the OTX pulses and their associated
indicators of compromise (IOCs) from your account.
This includes all of the following:
    - OTX pulses to which you subscribed through the web UI
    - Pulses created by OTX users to whom you subscribe
    - OTX pulses you created.
If this is the first time you are using your account, the download includes all pulses created by AlienVault.
All users are subscribed to these by default.
```
