# APPLICATION LOG FILE

## Logging to a KPEP-specific syslog file

All logging messages from KPEP use the "KPEP-" or "SEED-" prefix.  This can be used to filter the log messages for output to an alternative file rather than the default/global /var/log/syslog.

## Configure rsyslog to route Logs

You’ll need to create or modify an rsyslog configuration file to define routing rules based on the messager content:

1) Open or Create Configuration File:

    You can add custom rules in a new configuration file under /etc/rsyslog.d/.  To create a new file, use:

    ```text
    sudo nano /etc/rsyslog.d/10-kpep.conf
    ```

    The numeric value that the start of the filename is used to order the processing of each configuration file (lowest first).  The number you select should be low enough to guarantee these messages are not already logged before this configuraiton file is processed.

2) Add Routing Rules:

    In the configuration file, add rules to route the specific application’s logs to the desired file:

    ```text
    # Route log messages containing known prefixes to our custom log file
    if ($msg contains "KPEP-" or $msg contains "SEED-") then {
        action(type="omfile" file="/var/log/kpep.log")
        stop
    }
    ```

    With this filter, new syslog entries from any application or daemon that contain either of the keys 'KPEP-' or 'SEED-' are written to `/var/log/kpep.log`.  This includes the OpenSSL command line tool set, standard applications that link to OpenSSL via libcrypto, and custom applications such as kpep_rand and kpep_utility.

3) Save and Exit:

    Save the file and exit the editor.

## Set File Permissions

Ensure that rsyslog has the necessary permissions to write to the specified log file:

```text
sudo touch /var/log/kpep.log
sudo chown syslog:adm /var/log/kpep.log
sudo chmod 640 /var/log/kpep.log
```

## Reload Rsyslog Configuration

After making changes, reload rsyslog to apply the new configuration:

```text
sudo systemctl restart rsyslog
```

## Verify Configuration

Check the status of rsyslog to ensure it is running without errors:

```text
sudo systemctl status rsyslog
```

You can also check if the logs are being correctly written to the specified file:

```text
tail -f /var/log/kpep.log
```
