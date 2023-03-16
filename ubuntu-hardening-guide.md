# UBUNTU 10.04 / APACHE SERVER SETUP GUIDE

Includes build options for Laravel, WP, etc

## AWS - SMALL SERVER/DEVELOPMENT SERVER

In EC2, create a new instance.

Choose ubuntu 18.04 LTS.

Size \`micro\` or \`small\` suffice for most installations. Production sizes should be \`medium\` or larger.

Create and download a new PEM key, title it something that makes contextual sense. Such as:
\`server-key.pem\`

Create a new security group for devs, add your IP address+'/32' in the field, select ssh to allow access from your local.
Also add a rule to allow http port 80 and https port 443

All other defaults are fine, and can be modified to fit project spec.

### SSH

Use the \`connect\` button in the EC2 admin screen to get the ssh connection string

Test out your connection, add your your public key to the \`authorized_keys\` file in the \`.ssh\` directory.
To get your ssh key:
\`cat ~/.ssh/id_rsa.pub\`

* Timeouts when connecting to AWS are almost always security group misconfiguration, check that your IP is listed in the security group with ssh access port 22, and has a block ID after your IP of /32

Then remove password login for ssh:
\`sudo nano /etc/ssh/sshd_config\`
Set \`ChallengeResponseAuthentication no\` in that file

Then set auto-logout behavior (30-60 min is best)
\`sudo nano /etc/ssh/sshd_config\`
Set the following (timeout is in sec)
\`ClientAliveInterval 1800
ClientAliveCountMax 0\`
Then restart ssh
\`sudo systemctl restart ssh\`

### LOGIN SCREEN

Add a customized login screen by editing \`/etc/motd\`

Use the 'Big' ascii text generated on this site:
[ASCII Text Generator](\`<http://patorjk.com/software/taag/#p=display&f=Big&t=YourSIte\>`)

### DEPLOYMENT/APP USERS

Create a new user with no sudo access and no pw for deployments/git to run within.
\`sudo adduser *USERNAME*\`
\`sudo passwd -d *USERNAME*\`
Create an .ssh dir in that user's home dir
\`sudo mkdir /home/USERNAME/.ssh\`
And add your public key to a new \`authorized_keys\` file to login as that user (same as above)
\`sudo nano /home/USERNAME/.ssh/authorized_keys\`

Exit and test your connection with the new user, verify that the user cannot sudo.

### GIT

Ubuntu uses an older version of git. Update it with:
\`sudo add-apt-repository ppa:git-core/ppa\`
\`sudo apt-get update\`
\`sudo apt-get install git\`

Create a \`/var/www/html\` dir to host your repository.

Create a folder for your repo i.e. \`*YOURSITE*\`

Modify permissions on that folder to use the deployment user
\`sudo chown -R USERNAME:USERNAME *YOURSITE*\`

Create an empty repo and set the receive behavior to updateInstead:
\`git init\`
\`git config receive.denyCurrentBranch updateInstead\`

Add a remote to your local using the new user, make sure perms are all set to that deploy user:
\`git remote add staging USERNAME@ec2-1-11-111-111.us-east-2.compute.amazonaws.com:/var/www/html/staging.*YOURSITE*\`

Test out a push to the server:
\`git push staging HEAD:master --force\`

SSH in and verify your files have been updated.

### NODE

[Sourced from here](https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-18-04)
**Using the PPA version**
\`cd ~\`
\`curl -sL <https://deb.nodesource.com/setup_10.x> -o nodesource_setup.sh\`
\`sudo bash nodesource_setup.sh\`
\`sudo apt install nodejs\`
\`node -v\`

### NPM

The above script installs npm @v6, which is too old. Update it using:
\`sudo npm install npm -g\`

### ROUTE53

If Route53 is being used, go into the AWS console->route53 and add a line for a subdomain that points to your IP.
Click on 'hosted zones'->zone you want to modify->Create Record Set

Add a record set for the subdomain (staging/test) and the ip of the ec2 instance it's pointing to

### APACHE

[Pulled from this guide](https://www.digitalocean.com/community/tutorials/how-to-install-the-apache-web-server-on-ubuntu-18-04)
[And this one](https://www.howtoforge.com/tutorial/install-laravel-on-ubuntu-for-apache/)

Install apache & php@ latest:
\`sudo add-apt-repository ppa:ondrej/php\`
\`sudo apt-get update\`
\`
sudo apt-get install apache2  
sudo apt-get install libapache2-mod-php  
sudo apt-get install php  
sudo apt-get install php-xml
sudo apt-get install php-gd
sudo apt-get install php7.4-opcache (NOTE:needs v number i.e. php7.4-opcache)
sudo apt-get install php-mbstring
sudo apt-get install php7.4-curl
\`

Allow apache port 80 and 443 in the firewall (if ufw enabled):
\`sudo ufw allow 'Apache Full'\`

You can check the ufw status using:
\`sudo ufw status\`

Verify Apache is running after install:
\`sudo systemctl status apache2\`

Create a test \`index.html\` file in \`/var/www/html\`

Go to your ec2 instance's public IP and verify you see that file.

### APACHE PT 2, VHOSTS

Create a conf file to route traffic to your repo
\`sudo nano /etc/apache2/sites-available/staging.*YOURSITE*.conf\`

Basic conf looks like this for a laravel/vue build:

 \`<VirtualHost *:80>
    ServerName staging.YOURSITEURL
    DocumentRoot /var/www/html/staging.*YOURSITE*/public
    ServerAlias staging.YOURSITEURL
    <Directory /var/www/html/staging.*YOURSITE*/public>
        Options All
        AllowOverride All
        order allow,deny
        allow from all
    </Directory>
    ErrorLog /var/log/apache2/error.log
    RewriteEngine on
    RewriteCond %{SERVER_NAME} =staging.YOURSITEURL
    RewriteRule ^ <https://%{SERVER_NAME}%{REQUEST_URI>} [END,NE,R=permanent]
</VirtualHost>

<VirtualHost *:443>
    ServerName staging.YOURSITEURL
    DocumentRoot /var/www/html/staging.*YOURSITE*/public
    ServerAlias staging.YOURSITEURL
    ErrorLog /var/log/apache2/error.log
Header set Access-Control-Allow-Origin:*
    <Directory /var/www/html/staging.*YOURSITE*/public>
        Options All
        AllowOverride All
        order allow,deny
        allow from all
    </Directory>
</VirtualHost>\`

Enable mod_rewrite/headers/mysql, enable your site, disable the default 000 site, reload apache2
\`a2enmod headers\`
\`a2enmod rewrite\`
\`sudo a2ensite staging.*YOURSITE*.conf\`
\`sudo a2dissite 000-default.conf\`
\`sudo apt-get install php7.4-mysql\`
\`systemctl restart apache2\`

If route53 and apache are configured correctly, you should be able to hit your new url.
You can verify DNS using the following tool:
[MX Toolbox](https://mxtoolbox.com/DNSLookup.aspx)

### BASIC AUTH (if needed)

This will help keep out a lot of riff raff during development, just a simple encoded pw stored with apache. Makes it so only clients see the site
Add this to your \`<Virtualhost>\` port 443 block:

\`<Directory "/var/www/vhosts/YOURSITEURL">
    AuthType Basic
    AuthName "Restricted Content"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
    AllowOverride All
  </Directory>\`

Then you us htpasswd  to create the referenced file:
\`cd /etc/apache2 && touch .htpasswd\`
\`htpasswd -c .htpasswd USERNAME\`
Asks for a password and that's it! Restart apache to see the changes
[Ref](https://www.hostwinds.com/guide/create-use-htpasswd/)

### MYSQL/RDS

Create new RDS mysql instance with recommended "easy" settings in the RDS admin screen
Use a super secure password and non-standard admin username (devadmin), add to .env file sql connection on server

*Modify security settings to allow ip connections to port 3306 from the ec2 instance's PRIVATE ip address ONLY. This is changed by going to the RDS screen, and clicking on the name of the security group and changing INBOUND SETTINGS*

Test out connections using tcp over ssh pipe only, no raw sql connections from random IP's allowed

## LARAVEl SETTINGS

### COMPOSER/ARTISAN/NPM

Install composer
\`apt-get install composer\`

Install dependent php extensions/mysql
(composer install will tell you which ones it needs as well)
\`sudo apt-get install php7.4-mysql\`
\`sudo apt-get install php7.4-curl\`
\`sudo apt-get install php7.4-zip\`

Install npm
\`apt install npm\`

Install Yarn
Remove cmdtest yarn:
\`sudo apt-get remove cmdinstall cmdtest\`
[Then use this as a guide](https://linuxize.com/post/how-to-install-yarn-on-ubuntu-18-04/)

Build using composer & artisan, make sure that perms are correct:
\`composer install && php artisan optimize\`

These should not be necessary if you run npm/yarn/composer as your user, but are here if needed:
\`cd ../ && chown -R USERNAME:USERNAME staging.*YOURSITE*\`
\`chmod -R 777 storage/logs && chmod -R 777 storage/framework\`

Create a script next to the parent folder in \`var/www/html\` that builds and resets perms for server maintenance

### TESTING THE API ENDPOINT/MYSQL

Create a basic route to poc the api in \`api.php\`:
   \`Route::get('/user', function (Request $request) {\`
        \`return 'hola!';\`
    \`});\`

Create a basic route to poc the sql connection in \`api.php\`

\`Route::get('/users', 'UserController@show');\`

Make sure you have a \`show\` method that returns a model, like this:
 \`public function show(users $users)\`
    \`{\`
        \`//\`
        \`return $users->get();\`
    \`}\`

Go to the site, verify you see data. If no data, check with:
\`php artisan tinker\`
\`DB::connection()->getPdo();\` or \`Db::connection()->getDatabaseName();\`

## WORDPRESS SETTINGS
Touch and modify your \`.private-environment-settings.php\` file in the server dir. Use the following convention:
\`<?php
class ServerEnvironmentSettings {
    const dbName = 'DBNAME';
    const dbUsername = 'root';
    const dbPassword = '';
    const dbHost = 'localhost';
}
\`
*you will have to create the db manually through a dump if one has already been created locally*

Make sure that the \`wp_options\` table has the correct url for \`siteurl\` and \`home\`.
Make sure that \`wp_options\` \`permalinks\` row is empty

Create script to set file/folder permissions in the server directory:
*/var/www/html/resetPerms.sh*
\`#resets perms to proper WP settings
# server files are USERNAME:USERNAME
chown -R USERNAME:USERNAME *
# proper perms
find . -type f -exec chmod 644 {} +
find . -type d -exec chmod 755 {} +
chmod 644 staging.YOURSITE/.htaccess
chmod 644 prod.YOURSITE/.htaccess
# reset script to +x
chmod +x resetPermissions.sh
# chown uploads to www-data (server user)
chown -R www-data:www-data staging.YOURSITE/wp-content/uploads
chown -R www-data:www-data prod.YOURSITE/wp-content/uploads\`

*You may have to empty the \`active_plugins\` row in \`wp_options\` or do a pw reset if you get locked out using a basic password with wordfence activated*

ERROR:\`Publishing failed. Error message: The response is not a valid JSON response.\`
This is most likely due to a permalink error, try settting Settings->Permalinks to \`Plain\` if using a raw IP, or \`Post Name\` for a real url. See [this](https://passionwp.com/response-is-not-a-valid-json-response-error/) for more.

ERROR:\`Cannot upload media files\`
Verify that you have the dir \`wp-content/uploads\`, and that its perms are set to \`chmod 755\`. Re-run your perm script if \`uploads\` exists

### HTTPS

Use [certbot](https://certbot.eff.org/lets-encrypt/ubuntubionic-apache)

Run the following:
\`sudo apt-get update\`
\`sudo apt-get install software-properties-common\`
\`sudo add-apt-repository universe\`
\`sudo add-apt-repository ppa:certbot/certbot\`
\`sudo apt-get update\`
\`sudo apt-get install certbot python-certbot-apache\`

To obtain an apache cert:
\`sudo certbot --apache\`

Verify a cron is setup. Look in /etc/cron.* folders. Usually can been seen in this one:
\`EDITOR=nano /etc/cron.d\`

Test renewal:
\`sudo certbot renew --dry-run\`

### non-www redirect to www and http to https example:
<VirtualHost *:80>
   ServerName www.YOURSITE.org
    DocumentRoot /var/www/html/prod.YOURSITE
    ServerAlias YOURSITE.org

    <Directory /var/www/html/prod.YOURSITE>
        Options All -Indexes
        AllowOverride All
        order allow,deny
        allow from all
    </Directory>
    ErrorLog /var/log/apache2/error.log
    RewriteEngine on
    Redirect permanent / https://www.YOURSITE.org

SSLCertificateFile /etc/letsencrypt/live/www.YOURSITE.org/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/www.YOURSITE.org/privkey.pem
</VirtualHost>

<VirtualHost *:443>
   ServerName www.YOURSITE.org
   DocumentRoot /var/www/html/prod.YOURSITE
   ServerAlias YOURSITE.org
   ErrorLog /var/log/apache2/error.log
#  Header set Access-Control-Allow-Origin:*

    <Directory /var/www/html/prod.YOURSITE>
        Options All -Indexes
        AllowOverride All
        order allow,deny
        allow from all
    </Directory>

RewriteEngine on
RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteRule ^(.*)$ <https://www.%{HTTP_HOST}%{REQUEST_URI>} [R=301,L]

Include /etc/letsencrypt/options-ssl-apache.conf
SSLCertificateFile /etc/letsencrypt/live/YOURSITE.org/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/YOURSITE.org/privkey.pem
</VirtualHost>

### IMGMAGICK

[Ref](https://tecadmin.net/install-imagemagick-on-linux/)

\`sudo apt install php php-common gcc\`
\`sudo apt install imagemagick\`
\`sudo apt install php-imagick\`
\`sudo systemctl restart apache2\`

Test if installed:
\`php -m | grep imagick\`

### S3

[Ref](https://blog.larapulse.com/laravel/aws-s3-with-laravel-5)

Go to s3 in aws, create a new bucket, turn off "restrict public access".

For more security:

Go to IAM and click 'create new policy', click the 'JSON' tab
Add the following:

\`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::YOURSITE-staging"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::YOURSITE-staging/*"
        },
        {
            "Sid": "VisualEditor2",
            "Effect": "Allow",
            "Action": "s3:ListAllMyBuckets",
            "Resource": "*"
        }
    ]
}\`

Change \`YOURSITE-staging\` to whatever your bucket is called

Go to IAM->user->create user
Put in name, select 'attach existing policies directly', select the policy name you just created (this case is \`YOURSITE-staging\`)

Download the .csv and put the values in the server's \`.env\`

To test use tinker and see if you can list/create/see files:
\`php artisan tinker\`
\`Storage::disk('s3')->files();\`
\`Storage::disk('s3')->put('Hello.txt','hola muchacho!');\`
\`Storage::disk('s3')->files();\`
--Should show the file you just created

*If you run into issues, verify that the format of .env values is:*

FILESYSTEM_DRIVER=s3
AWS_ACCESS_KEY_ID=asfdb1234
AWS_SECRET_ACCESS_KEY=asdf1234/12341234
AWS_DEFAULT_REGION="us-east-2" (check s3 bucket region on right of page)
AWS_BUCKET=YOURSITE-staging
AWS_URL=BUCKETNAME.s3.REGIONNAME.amazonaws.com

You can also get url,bucket,region by getting a link to an uploaded file ex.:
\`<https://YOURSITE-staging.s3.us-east-2.amazonaws.com/profile.gif\>`

### NPM and permissions

ALL NPM related tasks should be run as the pipeline user (i.e. devadmin)
Once npm is installed with \`sudo apt install npm\`
Use (as devadmin user):
\`sudo chown -R $(whoami) ~/.npm\`
\`sudo chown -R $(whoami) /usr/lib/node_modules\`
Then run \`npm install\` and whatever build scripts in your build dir as the devadmin user

You may have to chmod permissions on files to allow devadmin user to create them

### GATSBY

Projects controlled by gatsby will need it installed with the root user
\`sudo npm install -g gatsby-cli\`

### PIPELINE

For a laravel-vue-spa build that requires the use of \`composer install\` and \`npm run dev\`
Use the following:

\`image: YOURREPO/build-common:latest
pipelines:
  branches:
    stage:
      - step:
          name: Staging deployment
          deployment: staging
          caches:
            - node
            - composer
            - vendor
          script:
            - git remote add stage $STAGE_REPO_PATH
            - git push stage HEAD:master --force
            - ssh $STAGE_SERVER 'cd /var/www/html/ && ./resetAndBuildStage.sh'
definitions:
  caches:
    vendor: ./vendor

\`

*Where ./resetAndBuildStage.sh is a script in /var/www/html that installs and sets permissions:*

\`#THIS SCRIPT IS USED WITH BITBUCKET PIPELINES TO BUILD LARAVEL-VUE PROJECTS
# RUN AS ROOT IF YOU HAVE BUILD ERRORS
cd staging.*YOURSITE*
composer dump-autoload && php artisan optimize
npm install
npm run dev
cd ../
chown -R USERNAME:USERNAME staging.*YOURSITE*
chmod -R 777 staging.*YOURSITE*/storage/logs
chmod -R 777 staging.*YOURSITE*/storage/framework\`

You will also need to configure environment variables for bitbucket, and add the approved list of IP's from bitbucket to your security group:
[Approved bitbucket IP'S](https://confluence.atlassian.com/bitbucket/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall-343343385.html)

As of 2020, they are:
34.199.54.113/32, 34.232.25.90/32, 34.232.119.183/32, 34.236.25.177/32, 35.171.175.212/32, 52.54.90.98/32, 52.202.195.162/32, 52.203.14.55/32, 52.204.96.37/32, 34.218.156.209/32, 34.218.168.212/32, 52.41.219.63/32, 35.155.178.254/32, 35.160.177.10/32, 34.216.18.129/32,52.8.84.222/32, 52.52.234.127/32, 104.192.136.0/21, 13.52.5.96/28

You can paste this whole list into the source ip input field, make sure to do this for the following ports:
22
80
7999

### WP CLI

Visit [here](https://wp-cli.org/) for detailed documentation. Otherwise, setup is simple:
\`
curl -O <https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar>
php wp-cli.phar --info
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp
wp --info
\`
`;

export const snippet2 = `
APACHE/UBUNTU HARDENING GUIDE EXTRAS:

# End user device (EUD) security guidance

From the UK National Cyber Security Centre

## <https://www.ncsc.gov.uk/collection/end-user-device-security/platform-specific-guidance/ubuntu-18-04-lts>

### Summary points

* Users should not be allowed to install arbitrary applications on the device. Applications should be authorised by an administrator and deployed via a trusted mechanism.
* Most users should have accounts with no administrative privileges. Users that require administrative privileges should use a separate unprivileged account for email and web browsing. It is recommended that local administrator accounts have a unique strong password per device.

**takeaway**

* NON-ADMIN user for everything but initial install/configuration on server
* installs are restricted to npm/git as much as possible

### Network Arch/Device provisioning

* handled by AWS, not relevant

### Authentication Policy

* Your organisation should have a consistent authentication policy which applies to all users and devices capable of accessing its data.

**takeaway**

* pw is removed for NON-ADMIN user, all authentication is based on ssh keys

### Boot process hardening

* handled by AWS, not relevant

### Updates

* This site recommends regular updates, specifically calling out Snap packages, their necessity to be sourced from the Ubuntu store, and maintaining regular updates.

### Privacy/VPN

* There are crash reporting and ping tools this site recommends turning off. These are largely for end ubuntu users rather than server clients
* This service recommends a VPN for end users. The AWS analogue to this is VPC which is in place

### Other notes

**leveraging auditd**

This is a syslogger with logs available at \`/var/log/audit/audit.log\`, will log any login/modifications from any user on the system. This includes pw changes, perm changes, access, etc.

Install using this command:
\`sudo apt-get install -y auditd\`

Add these lines to \`/etc/audit/rules.d/audit.rules\`

\`\`\`

## First rule - delete all

-D

## Increase the buffers to survive stress events

## Make this bigger for busy systems

-b 8192

## This determine how long to wait in burst of events

--backlog_wait_time 0

## Set failure mode to syslog

-f 1

## additional config logging user interaction/modification
## src<https://security.blogoverflow.com/2013/01/a-brief-introduction-to-auditd/>

-a always,exit -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -S clock_settime -k time-change
-a always,exit -S sethostname -S setdomainname -k system-locale
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/selinux/ -p wa -k MAC-policy
\`\`\`

# List of things for hardening Ubuntu

<https://gist.github.com/lokhman/cc716d2e2d373dd696b2d9264c0287a3>

## Force update, automatic security updates

\`\`\`
sudo apt-get update
sudo apt-get upgrade
sudo apt-get autoremove
sudo apt-get autoclean
\`\`\`

Automatic security updates are configured using \`unattended-upgrades\` which should already be correctly configured in \`/etc/apt/apt.conf.d/50unattended-upgrades\`

All \`--security\` lines in the \`Allowed-Origins\` section should be uncommented, everything else commented out:

\`\`\`
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
: Unattended-Upgrade::Allowed-Origins {
:     "\${distro_id}:\${distro_codename}-security";
: //  "\${distro_id}:\${distro_codename}-updates";
: //  "\${distro_id}:\${distro_codename}-proposed";
: //  "\${distro_id}:\${distro_codename}-backports";
: };
: // Unattended-Upgrade::Mail "my_user@my_domain.com";
\`\`\`

## Disabling root user and ubuntu, swapping in a hidden root

Multiple guides suggest completely disabling the root user, or at the very least turning off sudo access for root.
It is always regularly recommended to create a non-standard sudoer.

Steps:
* ssh in as ubuntu, run \`sudo su\`
* \`adduser USERNAME\`
* standard will be cl**where** is the first to letters of the repo
* input a secure pw (to be removed later)
* add them to the sudoers list \`usermod -aG sudo username\`
* set the user up for ssh access and no sudo pw:
  * \`sudo su && cd /home/USERNAME\`
  * \`sudo passwd -d USERNAME\` - remove pw
  * \`sudo mkdir /home/USERNAME/.ssh && chmod 600 /home/USERNAME/.ssh\`
  * \`sudo nano /home/USERNAME/.ssh/authorized_keys && chmod 600 /home/USERNAME/.ssh/authorized_keys\` -- add your public key here
  * make sure all .ssh files/folders are owned by that ssh user
  * remove sudo pw from new admin user \`USERNAME ALL=NOPASSWD: ALL\`, add this to \`/etc/sudoers.d/90-cloud-init-users\`
  * test login via ssh with new user, verify you can do things like \`ls -la /root\` for root privs
* disable root account
  * \`sudo passwd -l root\`
* if necessary, it can be re-enabled with \`sudo passwd -u root\`
* lastly, archive the ubuntu ssh login by running \`sudo mv /home/ubuntu /home/.ubuntu\`

## Swap

* not available

## systctl.conf

* This is a big part of hardening this server, prevents IP spoofing, logs suspicious packets, redirects.
* It also allows security during overflow events, leveraging ExecShield.
* IP spoof protection means DDOS protection, especially against \`syn flood\`
* Lastly, there is kernel panic protection, restarting the server during memory overage

* Add these lines to \`/etc/sysctl.conf\`
\`\`\`

# IP Spoofing protection

net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Block SYN attacks

net.ipv4.tcp_syncookies = 1

# Controls IP packet forwarding

net.ipv4.ip_forward = 0

# Ignore ICMP redirects

net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing

net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians

net.ipv4.conf.all.log_martians = 1

# Block SYN attacks

net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians

net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP broadcast requests

net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings

net.ipv4.icmp_echo_ignore_all = 1
kernel.exec-shield = 1
kernel.randomize_va_space = 1

# disable IPv6 if required (IPv6 might caus issues with the Internet connection being slow)

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Accept Redirects? No, this is not router

net.ipv4.conf.all.secure_redirects = 0

# Log packets with impossible addresses to kernel log? yes

net.ipv4.conf.default.secure_redirects = 0

# [IPv6] Number of Router Solicitations to send until assuming no routers are present

# This is host and not router

net.ipv6.conf.default.router_solicitations = 0

# Accept Router Preference in RA?

net.ipv6.conf.default.accept_ra_rtr_pref = 0

# Learn prefix information in router advertisement

net.ipv6.conf.default.accept_ra_pinfo = 0

# Setting controls whether the system will accept Hop Limit settings from a router advertisement

net.ipv6.conf.default.accept_ra_defrtr = 0

# Router advertisements can cause the system to assign a global unicast address to an interface

net.ipv6.conf.default.autoconf = 0

# How many neighbor solicitations to send out per address?

net.ipv6.conf.default.dad_transmits = 0

# How many global unicast IPv6 addresses can be assigned to each interface?

net.ipv6.conf.default.max_addresses = 1

# In rare occasions, it may be beneficial to reboot your server reboot if it runs out of memory

# This simple solution can avoid you hours of down time. The vm.panic_on_oom=1 line enables panic

# on OOM; the kernel.panic=10 line tells the kernel to reboot ten seconds after panicking

 vm.panic_on_oom = 1
 kernel.panic = 10
\`\`\`

* enable settings with \`sudo sysctl -p\`

### Verify OpenSSL is new enough to prevent Heartbleed

\`openssl version -v\` needs to output 1.0.1f or higher, otherwise raw sysinfo can be hacked

### Securing /tmp directories

- This will prevent executables in /tmp and /var/tmp. Attackers make use of /tmp as it is usually 777 and can server as a staging area for scripts.

\`\`\`

# Let's create a 1GB (or what is best for you) filesystem file for the /tmp parition

sudo fallocate -l 1G /tmpdisk
sudo mkfs.ext4 /tmpdisk
sudo chmod 0600 /tmpdisk

# Mount the new /tmp partition and set the right permissions

sudo mount -o loop,noexec,nosuid,rw /tmpdisk /tmp
sudo chmod 1777 /tmp

# Set the /tmp in the fstab

sudo nano /etc/fstab
ADD THIS-> /tmpdisk /tmp ext4 loop,nosuid,noexec,rw 0 0
sudo mount -o remount /tmp

# Secure /var/tmp by repeating the steps above

\`\`\`
* test by creating a \`hello.sh\` in /tmp that echoes something, run \`chmod +x hello.sh && ./hello.sh\` to check perms

### IP spoofing with hosts

Handled by google and others, no longer relevant from this tut

### Add a basic antivirus and daily scan

- clamscan should be available, you can test this with \`sudo freshclam\`. If you get an error it's running
* schedule a nightly cron to output found errors into logs
  * \`sudo apt-get install clamav-daemon\` //installs the daemon
  * \`sudo mkdir /home/ROOTUSER/clamscan && chmod 700 /home/ROOTUSER/clamscan\`//creates log dir
  * sudo crontab -e
    * \`00 00 ** * clamscan -r /location_of_files_or_folder | grep FOUND >> /home/ROOTUSER/clamscan/scanned-\`date +\%Y\%m\%d\%H\%M\%S\`.txt\`
  * ex \`\`\`clamscan -r /var/www/html | grep FOUND >> /home/clac/clamscan/scanned-\`date +\%Y\%m\%d\%H\%M\%S\`.txt\`\`\`
  * add a crontab line for auto-removal of older logs (-10 days)
    * \`01 00 ** *find /home/ROOTUSER/clamscan/* -mtime +10 -exec rm {} \;\`

# How to Harden your Ubuntu 18.04 Server

<https://medium.com/@BaneBiddix/how-to-harden-your-ubuntu-18-04-server-ffc4b6658fe7>

* Most of these are covered by the above.
* 3 interesting notes came up for SSH hardening and fail2Ban.

### SSH Hardening

* Regenerate host keys (do this before setting up users for SSH)
 \`rm /etc/ssh/ssh_host_* && ssh-keygen -A\`
* Change ciphers and algorithms to stronger versions. Add this to \`/etc/ssh/sshd_config\`
\`\`\`
KexAlgorithms curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2–512-etm@openssh.com,hmac-sha2–256-etm@openssh.com,umac-128-etm@openssh.com
\`\`\`

### ssh-audit
This is a script that outputs a ton of info on the ssh config of the server, and makes recommendations

<https://github.com/jtesta/ssh-audit/>

* On a local dev box, clone the repo and audit via \`python ssh-audit.py yoursite.com\`

### Fail2Ban

Fail2Ban bans IPs with malicious/suspicious login activity/server log activity. Great for preventing port sniffing/etc.

<https://www.fail2ban.org/wiki/index.php/Main_Page>

* install using \`sudo apt-get install fail2ban\`
* check if running with \`fail2ban-client status\`
* check for REJECT lines (fail2Ban is working) using \`sudo iptables -L f2b-sshd\`

# Apache Hardening Guide

* Remove indexing on folders
  * In the server's \`.conf\` file, add this to both :80 and :443 blocks:
  \`\`\`<Directory /YOURDIR>
  //add this line:
   Options All -Indexes
  </Directory>\`\`\`
* Prevent Etag (allows attackers to get info on process/MIME info)
  * Add this to the server's .conf files: \`FileETag None\` above the \`<Directory>\`
  * This also forces assets to be dependent on 'Expires' or 'Cache-control' headers over server caching static assets

* Turn off TRACE requests
  * \`TraceEnable off\` added above \`<Directory>\`

* Force HTTPS cookies and do not allow page to be served in an iframe with X-Frame-Options
 \`\`\`Header always append X-Frame-Options SAMEORIGIN
 Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure\`\`\`

* ModSecurity is a application firewall, it is available and configurable, but many of the techniques are covered by other settings above
