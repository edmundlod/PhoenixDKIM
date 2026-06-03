%global upname PhoenixDKIM

Name:           phoenixdkim
Version:        1.0.0
Release:        1%{?dist}
Summary:        Security-focused DKIM signing and verifying milter

License:        BSD-3-Clause AND Sendmail-Open-Source-1.1
URL:            https://github.com/edmundlod/PhoenixDKIM
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        phoenixdkim.conf.sample

BuildRequires:  cmake >= 3.20
BuildRequires:  gcc
BuildRequires:  pkgconfig
BuildRequires:  sendmail-milter-devel
BuildRequires:  lmdb-devel
BuildRequires:  unbound-devel
BuildRequires:  lua-devel
BuildRequires:  openssl-devel >= 3.0
BuildRequires:  libevent-devel
BuildRequires:  nettle-devel
BuildRequires:  hiredis-devel
BuildRequires:  libcurl-devel
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros

# strlcpy/strlcat landed in glibc 2.38 (Fedora 39+, RHEL 10+); older EPEL needs libbsd
%if 0%{?rhel} && 0%{?rhel} <= 9
BuildRequires:  libbsd-devel
%endif

%{?systemd_requires}

Requires:       lib%{name}%{?_isa} = %{version}-%{release}

%description
PhoenixDKIM is a standalone DKIM signing and verification milter, descended
from OpenDKIM, with a focus on security and correctness. It uses the OpenSSL 3
EVP API, signs with RSA and Ed25519 (RFC 8463), and drops weak crypto
(no RSA-SHA1 signing; 2048-bit key minimum). It reads OpenDKIM-style key and
signing tables.

DKIM provides a way for senders to confirm their identity when sending email
by adding a cryptographic signature to the headers of the message.

%package -n lib%{name}
Summary:        PhoenixDKIM shared library

%description -n lib%{name}
Shared library for PhoenixDKIM DKIM signing and verification.

%package -n lib%{name}-devel
Summary:        Development files for lib%{name}
Requires:       lib%{name}%{?_isa} = %{version}-%{release}

%description -n lib%{name}-devel
Headers and development library for building against libphoenixdkim.

%package tools
Summary:        Utilities for administering PhoenixDKIM

%description tools
Command-line tools for PhoenixDKIM: %{name}-genkey, %{name}-genzone,
%{name}-testkey, and %{name}-testmsg.

%prep
%autosetup -n %{upname}-%{version}

cat > %{name}.sysusers.conf << 'EOF'
u phoenixdkim - 'PhoenixDKIM Milter' /run/phoenixdkim -
m phoenixdkim mail
EOF

%build
%cmake
%cmake_build

%install
%cmake_install

install -d %{buildroot}%{_sysconfdir}/%{name}
install -Dm 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf
install -d %{buildroot}%{_sysconfdir}/%{name}/keys
install -d %{buildroot}%{_localstatedir}/spool/%{name}
install -Dm 0644 %{name}.sysusers.conf %{buildroot}%{_sysusersdir}/%{name}.conf

find %{buildroot}%{_libdir} -name '*.a' -delete

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%ldconfig_scriptlets -n lib%{name}

%files
%license LICENSE LICENSE.Sendmail
%doc FEATURES KNOWNBUGS RELEASE_NOTES RELEASE_NOTES.Sendmail
%{_sbindir}/%{name}
%{_unitdir}/%{name}.service
%{_sysusersdir}/%{name}.conf
%{_mandir}/man8/%{name}.8*
%{_mandir}/man5/%{name}.conf.5*
%dir %attr(-,root,%{name}) %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%dir %attr(0750,root,%{name}) %{_sysconfdir}/%{name}/keys
%dir %attr(-,%{name},%{name}) %{_localstatedir}/spool/%{name}

%files -n lib%{name}
%license LICENSE LICENSE.Sendmail
%{_libdir}/lib%{name}.so.0*

%files -n lib%{name}-devel
%license LICENSE LICENSE.Sendmail
%{_includedir}/%{name}/
%{_libdir}/lib%{name}.so
%{_libdir}/pkgconfig/lib%{name}.pc
%{_mandir}/man3/%{name}-lua.3*

%files tools
%license LICENSE LICENSE.Sendmail
%{_bindir}/miltertest
%{_sbindir}/%{name}-genkey
%{_sbindir}/%{name}-genzone
%{_sbindir}/%{name}-testkey
%{_sbindir}/%{name}-testmsg
%{_mandir}/man8/miltertest.8*
%{_mandir}/man8/%{name}-genkey.8*
%{_mandir}/man8/%{name}-genzone.8*
%{_mandir}/man8/%{name}-testkey.8*
%{_mandir}/man8/%{name}-testmsg.8*

%changelog
* Tue Jun 03 2026 Edmund Lodewijks <imnaym9vr@mozmail.com> - 1.0.0-1
- Initial package
