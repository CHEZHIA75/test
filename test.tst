class prometheus_jmx_exporter(
  String           $exporter_version = '1.5.0',

  String           $install_dir      = '/opt/prometheus/jmx_exporter',
  String           $config_dir       = '/etc/prometheus/jmx_exporter',

  String           $user             = 'prometheus',
  String           $group            = 'prometheus',

  String           $listen_address   = $facts['networking']['ip'],
  Integer          $listen_port      = 9104,

  Optional[String] $host_port        = undef, # e.g. "weblogic01:7001"
  Optional[String] $jmx_url          = undef, # e.g. "service:jmx:rmi:///jndi/rmi://weblogic01:7001/jmxrmi"
  Optional[String] $jmx_username     = undef,
  Optional[String] $jmx_password     = undef,
  Boolean          $ssl              = false,

  # ---- internal artifact coordinates (match your org naming) ----
  String           $artifact_path    = "gen-jfrog/jmx_exporter/jmx_exporter_v${exporter_version}.tar.gz",
  String           $jar_name         = "jmx_prometheus_standalone-${exporter_version}.jar",
) {

  require soe_linux
  include dc_stdlib
  include prometheus_jmx_exporter::firewall
  include system

  if $host_port == undef and $jmx_url == undef {
    fail('prometheus_jmx_exporter: set either $host_port or $jmx_url')
  }

  # Standalone runs as a java process
  package { 'java-11-openjdk-headless':
    ensure => installed,
  }

  file { [$install_dir, $config_dir]:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Download+extract exporter from internal binrepo (Option C pattern)
  $binrepo_url  = lookup('dept::binrepo_url')
  $artifact_url = "${binrepo_url}/${artifact_path}"

  archive { '/tmp/jmx_exporter':
    ensure       => present,
    source       => $artifact_url,
    extract      => true,
    extract_path => "${install_dir}/",
    creates      => "${install_dir}/${jar_name}",
    cleanup      => true,
    user         => $user,
    group        => $group,
    require      => File[$install_dir],
    notify       => Service['prometheus-jmx-exporter'],
  }

  # JMX exporter config file (standalone server mode)
  file { "${config_dir}/config.yaml":
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp("${module_name}/jmx_exporter_config.yaml.epp", {
      'host_port'    => $host_port,
      'jmx_url'      => $jmx_url,
      'jmx_username' => $jmx_username,
      'jmx_password' => $jmx_password,
      'ssl'          => $ssl,
    }),
    require => File[$config_dir],
    notify  => Service['prometheus-jmx-exporter'],
  }

  # Systemd unit (matches your node_exporter approach)
  file { '/etc/systemd/system/prometheus-jmx-exporter.service':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => epp("${module_name}/etc_systemd_system_prometheus-jmx-exporter.service.epp", {
      'user'           => $user,
      'group'          => $group,
      'jar_path'       => "${install_dir}/${jar_name}",
      'listen_address' => $listen_address,
      'listen_port'    => $listen_port,
      'config_file'    => "${config_dir}/config.yaml",
    }),
    require => [Archive['/tmp/jmx_exporter'], File["${config_dir}/config.yaml"]],
    notify  => Exec['systemd-daemon-reload-prometheus-jmx-exporter'],
  }

  exec { 'systemd-daemon-reload-prometheus-jmx-exporter':
    command     => '/bin/systemctl daemon-reload',
    refreshonly => true,
    path        => ['/bin', '/usr/bin'],
  }

  service { 'prometheus-jmx-exporter':
    ensure  => running,
    enable  => true,
    require => [Package['java-11-openjdk-headless'], File['/etc/systemd/system/prometheus-jmx-exporter.service']],
  }
}
