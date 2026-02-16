<% if $host_port { -%>
hostPort: "<%= $host_port %>"
<% } -%>
<% if $jmx_url { -%>
jmxUrl: "<%= $jmx_url %>"
<% } -%>

<% if $jmx_username { -%>
username: "<%= $jmx_username %>"
<% } -%>
<% if $jmx_password { -%>
password: "<%= $jmx_password %>"
<% } -%>

ssl: <%= $ssl ? { true => 'true', default => 'false' } %>

rules:
  - pattern: '.*'
