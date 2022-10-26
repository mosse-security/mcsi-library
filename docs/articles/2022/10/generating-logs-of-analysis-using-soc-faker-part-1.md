:orphan:
(generating-logs-of-analysis-using-soc-faker-part-1)=

# Generating Logs for Analysis Using SOC-Faker: Part I

One of the most important parts of learning how to do log analysis is to have a good set of logs to work with. There is a tool that can help with this - [SOC-Faker](https://github.com/swimlane/soc-faker). SOC-Faker is a tool that generates random logs, based on a set of templates. This can be a great way to get a feel for working with logs, testing IDS sensors, or tuning alerts. In this article, we'll take a look at how to use SOC-Faker to generate random logs for learning log analysis.

## The benefits of using SOC-Faker for log analysis 

SOC-Faker can help with log analysis by creating fake logs that can be used to test entire organizational capabilities such as the Security Operations Center.  It can also be used for:
- Log based intrusion detection systems
- Testing alert thresholds
- Continuous testing of security alerting mechanisms
- Training new SOC or security analysts

Often threat hunters or security analysts want sample logs of malicious activity but may only find a limited number online.  Other times, it may require recreating an attack using adversary emulation.  When those types of options are not available, SOC-Faker expedites the process by generating a virtually unlimited number of logs in a variety of formats.

## Installing SOC-Faker

To use SOC-Faker, you first need to install it on your system. Then, you can use the SOC-Faker command line interface to generate logs. The syntax is very simple - you just need to specify the logs you want to generate.

The easiest way to install SOC-Faker is to use their pip module.

<code>

    pip3 install soc-faker --user

</code>

## Using SOC-Faker

The documentation on the SOC-Faker GitHub page has many examples of how to generate a variety of logs.  Here is an example if you wanted to generate 20 email messages:

<code>
    
    import json

    from socfaker import SocFaker

    sc = SocFaker()

    i = 0
    num = 20

    while (i <= num):
            
            print(sc.email.email)
            i += 1
</code>

The code above could be used for testing spam filters or test alerting when an email originates from a suspicious domain or threat hunting for suspicious [emails performing data exfiltration](https://library.mosse-institute.com/articles/2022/04/email-another-source-for-data-exfiltration/email-another-source-for-data-exfiltration.html#email-another-source-for-data-exfiltration).  New datasets can be added and customized based on an organization's risk profile.  For example, if you are creating hunts for SQL injection attempts on web servers, you could customize the *useragent.json* file for SOC-Faker.

Sqlmap is an automated tool to detect and enumerate databases that are exposed due to insecure web forms or APIs. If you have a tool and what to alert for sqlmap being used against a public web server, logs could be generated with the sqlmap user-agent by adding it to the end of the dictionary in *socfaker/data/useragent.json*:

<code>

    , "sqlmap": ["sqlmap/1.3.11#stable (http://sqlmap.org)"] }
    
</code>

(or the entire dictionary in *useragent.json* could be removed and customized to your environment) and then add it to the **BROWSER_LIST** in *socfacker/useragent.py*

<code>
    
    BROWSER_LIST = [
        'Firefox', 
        'Internet+Explorer', 
        'Opera', 
        'Safari', 
        'Chrome', 
        'Edge', 
        'Android+Webkit+Browser',
        'sqlmap'
    ]
</code>

In this case, it would be useful to generate a large number of logs and smaller ones and test your alert to see if it detects *sqlmap* entries in the appropriate log file.

## Generating logs

When generating logs, the output is a Python Dictionary.  For example:

<code>

    import json
    from socfaker import SocFaker

    sc = SocFaker()

    print(sc.http.request)

</code>

could print:

<code>

    {'body': {'bytes': 3162, 'content': 'Hello World'}, 'bytes': 716, 'method': 'delete', 'referrer': 'http://www.basket.magenta.nowruz:80/fpadmin;ids/?id=212be817-e204-42d5-adc7-c65a56414d87'}

</code>

To extract the "bytes," "method" and "referrer," the code below could work:

<code>
    
    print("Method: " + x["method"])
    print("Bytes: " + str(x["bytes"]))
    print("Referrer: " + x["referrer"])
    print("---------------------------")

</code>

would print:

<code>

    Method: delete
    Bytes: 716
    Referrer: http://www.basket.magenta.nowruz:80/fpadmin;ids/?id=212be817-e204-42d5-adc7-c65a56414d87
    ---------------------------

</code>

## SOC-Faker CLI

When SOC-Faker is installed, it also includes a commandline tool named "soc-faker."

To generate a random log with file statistics on suspicious files, run:

<code>

    soc-faker file

</code>

<code>

    {'accessed_timestamp': '2022-10-14T11:29:21.630557-04:00', 'attributes': ['hidden', 'readonly'], 'build_version': '30780', 'checksum': '48784ab8a5a282d79032ced635ce218e', 'directory': 'C:', 'drive_letter': 'Z', 'extension': 'sys', 'full_path': 'C:\\Windows\\WinSxS\\amd64_dual_wdmaudio.inf_31bf3856ad364e35_10.0.17763.1_none_9f91a9d8a3e03bbe\\drmkaud.sys', 'gid': 4164, 'hashes': {'md5': '48784ab8a5a282d79032ced635ce218e', 'sha1': '527b90a749ab4a7ad329ee16b4df023d38ff8539', 'sha256': '42ba75e0d1fe7d63aac4aab0f9051c171f4ed8ac5f32da943272b9ba18b7582d'}, 'install_scope': 'user-local', 'md5': '48784ab8a5a282d79032ced635ce218e', 'mime_type': 'application/vnd.ims.imsccv1p2', 'name': 'drmkaud.sys', 'sha1': '527b90a749ab4a7ad329ee16b4df023d38ff8539', 'sha256': '42ba75e0d1fe7d63aac4aab0f9051c171f4ed8ac5f32da943272b9ba18b7582d', 'signature': 'Microsoft Windows', 'signature_status': 'Counterfit', 'signed': 'True', 'size': ['513861.78KB', '501.82MB'], 'timestamp': '2016-11-04T02:08:49.635550-04:00', 'type': 'symlink', 'version': '6.1.4516.69447'}
</code>

Adding the **-h** switch will print available options for the log being generated.  For example, in the above command:

<code>

    soc-faker file -h

</code>

will print all available fields so:

<code>

    soc-faker file full_path

</code>

could print:

<code>

    C:\Windows\System32\DynamicMedium.bin

</code>
.  That allows generating custom logs that are not in the SOC-faker program by combining the various log generation options.

## Conclusion

SOC-Faker is a small python library that can help you with log analysis. It provides many types of data logs that can be used for a variety of purposes.  Anytime you are testing code on logs, always test on a small dataset before applying it to a large dataset. SOC-Faker can be used to generate a small or large dataset.  Also, if you have some basic skills in Python programming, the datasets it uses to generate logs can be customized for your unique organizational use cases.  In the next article, we'll look at some ways to automate the generation of logs using SOC-Faker.

:::{seealso}
Want to learn practical Threat Hunting tactics and strategies? Enrol in [MTH - Certified Threat Hunter Certification](https://www.mosse-institute.com/certifications/mth-certified-threat-hunter.html)
:::