:orphan:
(aws-password-policies-know-your-options)=
# AWS Password Policies: Know Your Options
 

Most of the time, you will need a password to complete your actions in AWS. The password is set when you register the account, and you may modify it at any time by visiting the Security Credentials page. Let's learn what are your different password policy options.

## Password Administration: Policies

The choices available for setting a password policy for your account are described below. They all require at least:

**one capital letter**: You can demand at least one capital character from the International Organization for Standardization (ISO) basic Latin alphabet in IAM client passwords (A to Z).

**one lower-case character**: You may make it compulsory for your user passwords to have at minimum one lower-case letter ranging from _a to z_.

**a single number**: You may make it compulsory for your IAM user passwords to have at least one numeric character (from 0 to 9).

**one unique non-alphanumeric character**: An alpha-numeric character comprises of numbers and alphabet. You can also require IAM user passwords to include at minimum one of the these non alphabet or number including symbols : ! @ # $ % & \ * ( ) + - = [ ] \|

You have also various other options as follows:

**Minimum password**: You may define the minimum number of characters required in an IAM user password via a password policy. The allowed range is any number between 6 and 128.

**iam:ChangePassword action**: You may also grant IAM users pertaining to your account _ChangePassword_ action. They may then use the IAM dashboard to update their personal passwords.

**Password expiry**: IAM user passwords can be set to be viable for a specific amount of days. You define how long passwords are usable once they are created. You may set the password end date to anything from 1 to 1,095 days.

**Password reuse**: Prevent IAM users, using the same password again. You may limit the number of former passwords that IAM members can use. The number of earlier passwords can be adjusted from 1 to 24, included.

## Other password policy considerations

- You may restrict IAM members from changing their password when their existing one expires.

- If you prevent a user from selecting a new password following expiration, the user will be prompted to create a new password prior to gaining access to the AWS Management Console.

- You can also restrict certain clients from managing passwords. If you provide your IAM members the ability to update their own passwords, IAM automatically gives them access to the password policy. To establish a password that conforms with the policy, IAM users must be granted access to the account's password policy.
- When a password expires, an system administrator must restore it.
- When an IAM user's password is about to expire, the AWS Management Console notifies them (15 days before expiration). Members of IAM may update their passwords provided that they are permitted for this action. Once they reset the password, the rotating time for that password begins again.
- An IAM user can only have one active password at that time.

### Conclusion

Upon completion of this blog post, now you know which password policy options you have that you can implement according to your business needs.

> **Want to learn practical cloud skills? Enroll in MCSI’s - [MCSF Cloud Services Fundamentals ](https://www.mosse-institute.com/certifications/mcsf-cloud-services-fundamentals.html)**