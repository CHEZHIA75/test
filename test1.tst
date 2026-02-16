[Unit]
Description=Prometheus JMX Exporter (standalone)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<%= $user %>
Group=<%= $group %>
ExecStart=/usr/bin/java -jar <%= $jar_path %> <%= $listen_address %>:<%= $listen_port %> <%= $config_file %>
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
