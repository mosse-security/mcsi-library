:orphan:
(root-login-vs-sudo)=
# Root Login vs. Sudo
 

This blog will explain why you should quit logging in as root at all times and provide the best security alternative to doing so.

## The risks associated with signing in as the root user

The root user is the strongest admin on a Unix or Linux computer. You have total command of the system while logged in as the root user. But, continuously signing in as the root user might cause a few security issues.

Signing in as the root user makes it simple for you or someone else to do a system-damaging activity unintentionally. So, if you always log in as the root user, or even simply make the root user account easily available, it means that you're doing a great deal of work for attackers and intruders.

The only way to allow users to conduct administrative jobs is to give them all the root credentials. What if one of those users decided to leave the corporation? You don't want that individual to be able to sign in to the systems, so you'd have to reset the password and give the new one to all other users. And what if you only want people to have admin capabilities for specific tasks rather than complete root privileges?

All you need is a good technique that allows users to conduct admin jobs without the danger of always logging in as the root user, and that also allows users to have only the admin credentials necessary to execute certain tasks. That method exists on Linux and Unix in the form of the sudo tool which we will cover in the upcoming section.

## The Benefits of Using Sudo

When used correctly, the sudo tool may dramatically improve system security while also making an administrator's work easier.

You may use sudo to do a number of things:

- Grant some users complete administrative rights, while granting other users the permissions they require to accomplish things directly connected to their professions.
- Enable users to execute administrative activities by providing their individual regular user credentials, eliminating the need to disseminate the root password to everyone. Make it more difficult for attackers to get access to your systems.

If you use sudo and deactivate the admin account, potential attackers won't know which user account to target since they won't know which one has admin rights. Establish sudo policies that you can apply over an entire company network. You'll be able to observe what people are doing with their administrative privileges, which will improve your monitoring skills.

## Summary

In this blog article, we discussed the security risks inherent with utilizing the root account and what and we should instead use: Sudo.

Sudo allows for elaborate access control by providing admin rights to just the services that require them. In conclusion, Logging in as Sudo improves our systems security by decreasing the attack surface.

> **Do you want to get practical skills to work in cybersecurity or advance your career? Enrol in [MCSI Bootcamps](https://www.mosse-institute.com/bootcamps.html)!**