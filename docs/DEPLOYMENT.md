# Deployment

This document explains how to run ficus-relay, a Banyan relay built on strfry, on its own VM, for example on a cloud provider like DigitalOcean, Linode, AWS or Vultr. The binary is still called `strfry`.

## Starting & Endpoint

We'll assume you have a running VPS that you have access to:

- You can ssh to the node
- You have the IP address of the node
- You can use some kind of DNS registrar to point some domain at the node

The goal is to have:

- A running Banyan relay, with its admin page
- With a letsencrypt certificate

## Provision your server

The remainder of the document assumes a plain VPS.

Vultr - $12/mo
- High performance Intel
- 1 vCPU
- 2048 MB Ram
- 50 GB NVMe SSD
- OS Ubuntu 24.04 LTS
- Disable automatic backup

The harvester fetches the notes of every universe from other relays, so plan disk space for it: a well-connected person with `banyan.harvester.backfillDays = 60` brought in about 190k events.

## Point DNS at your server

While you wait for your server to provision, go to your DNS provider and point an address at it.  An A record of `relay.yourdomain.com` should point to the IP address of your VPS.

## Install the relay

Either run the Docker image, or build from source.

### With Docker

The image is published as `ghcr.io/nogringo/ficus-relay:latest`, for amd64 and arm64. Copy [strfry.conf](../strfry.conf), edit it as described in [Configure the relay](#configure-the-relay) below, then start it with [sample-docker-compose.yaml](../sample-docker-compose.yaml):

        docker compose -f sample-docker-compose.yaml up -d

Inside the container the config is `/etc/strfry.conf` and the database `/app/strfry-db`, so keep `db = "./strfry-db/"` and set `bind = "0.0.0.0"`. Then skip to [nginx](#sample-nginx-starter-config).

### From source

        # Update deps
        sudo apt update

        # Download ficus-relay
        git clone https://github.com/nogringo/ficus-relay.git
        cd ficus-relay

        # Install compilation dependencies
        sudo apt install -y git build-essential libyaml-perl libtemplate-perl libregexp-grammars-perl libssl-dev zlib1g-dev liblmdb-dev libflatbuffers-dev libsecp256k1-dev libzstd-dev libcurl4-openssl-dev ufw

        # Build it
        git submodule update --init
        make setup-golpe
        make -j2

        # Go get coffee, this takes a few minutes on a single vCPU

        # Install the binary
        sudo cp strfry /usr/local/bin

        # Install web hosting dependencies
        sudo apt install nginx certbot python3-certbot-nginx

        # Remove the default nginx file
        sudo rm -rf /etc/nginx/sites-available/default

        # Provide the following settings file
        sudo vim /etc/nginx/sites-available/default

        sudo service nginx restart

Note, at this point your nginx will just try to pass all connections to a nonexistent relay endpoint, get frustrated, and refuse the connection.

- Create user

        sudo useradd -M -s /usr/sbin/nologin strfry

- Create data directory

        sudo mkdir /var/lib/strfry
        sudo chown strfry:strfry /var/lib/strfry
        sudo chmod 755 /var/lib/strfry


### Sample NGINX Starter Config

Note here you'll use the DNS name you configured above. Keep the `Host` header: each person's relay is a path on this host.

        server{
            server_name relay.yourdomain.com;
            location / {
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Host $host;
                proxy_pass http://127.0.0.1:7777;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection "upgrade";
            }
        }

## Configure the relay

Edit the `db = "./strfry-db/"` line to: `db = "/var/lib/strfry/"` (not with Docker).

Check system hard limit `ulimit -Hn`

If for example `524288` can set this to `nofiles = 524288` in strfry.conf (or set to 0)

Two Banyan settings are required. The public URL, without a path, is used for NIP-42 AUTH on each person's relay and for the NIP-98 signatures of the admin page:

        relay {
            auth {
                serviceUrl = "wss://relay.yourdomain.com"
            }
        }

And the admins, the only keys that can add people:

        banyan {
            admins = "npub1youradminkey..."
        }

Behind nginx, set `relay.realIpHeader = "x-forwarded-for"` so the logs show the clients' addresses. The other Banyan settings, with their defaults, are in the `banyan` section of strfry.conf and described in [banyan.md](banyan.md).

Copy the strfry.conf file to /etc and change ownership:

        sudo cp strfry.conf /etc/strfry.conf
        sudo chown strfry:strfry /etc/strfry.conf

### Install Systemd File

Put the following file at /etc/systemd/system/strfry.service

        [Unit]
        Description=ficus-relay (Banyan relay)

        [Service]
        User=strfry
        ExecStart=/usr/local/bin/strfry relay
        Restart=on-failure
        RestartSec=5
        ProtectHome=yes
        NoNewPrivileges=yes
        ProtectSystem=full
        LimitCORE=1000000000

        [Install]
        WantedBy=multi-user.target

Now enable this service and start it

        sudo systemctl enable strfry.service
        sudo systemctl start strfry

        sudo systemctl status strfry

You can curl to ensure things are running:

        curl localhost:7777

Tells you that the relay is running

        curl localhost:80

Tells you that nginx is running

### Firewall and Certificate

Now let's open the port to the outside world. The harvester connects out to other relays and to the LNURL servers of zap recipients, so outgoing traffic must stay allowed.

        sudo ufw allow 'Nginx Full'
        sudo ufw status
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        ufw allow 22/tcp # allow incoming SSH traffic
        sudo ufw enable

For added security you can `sudo apt install -y fail2ban`

        sudo certbot --nginx -d relay.yourdomain.com

## Add people

Open `https://relay.yourdomain.com/admin` with a NIP-07 browser extension holding an admin key, and add a person with a slug. Their relay is then live at `wss://relay.yourdomain.com/<slug>`, and its trust universe fills up as the harvester fetches their engagement. The same works from the server:

        sudo -u strfry strfry --config /etc/strfry.conf banyan add npub1... alice

People manage their own relay on the same page, signed in with their own key: weights, circles, pins, blocks, muted threads, and a remote signer for relays that only serve them their own data.

## Upgrade

        git pull
        make update-submodules
        make -j2
        sudo cp strfry /usr/local/bin
        sudo systemctl restart strfry

With Docker: `docker compose -f sample-docker-compose.yaml pull` then `up -d`.
