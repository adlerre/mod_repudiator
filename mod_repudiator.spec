Name:           mod_repudiator
Version:        0.1.0
Release:        1%{?dist}
Summary:        Reputation-based limiting/blocking of malicious clients for Apache

Group:          System Environment/Daemons
License:        GPLv2+
URL:            https://github.com/adlerre/mod_repudiator
Source0:        mod_repudiator.c
Source1:        mod_repudiator.conf
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  httpd-devel
BuildRequires:  libmaxminddb-devel
BuildRequires:  pcre2-devel
Requires:       httpd
Requires:       httpd-mmn = %([ -a %{_includedir}/httpd/.mmn ] && cat %{_includedir}/httpd/.mmn || echo missing)

%description
Reputation-based limiting/blocking of malicious clients for Apache

%build
apxs -DPCRE2 -lmaxminddb -lpcre2-8 -Wc,"%{optflags}" -c %{SOURCE0}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -pm 755 \
    $RPM_BUILD_ROOT%{_libdir}/httpd/modules \
    $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d
install -pm 755 %{_sourcedir}/.libs/mod_repudiator.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules/
install -pm 644 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/httpd/conf.d/*
%{_libdir}/httpd/modules/*


%changelog
* Wed May 7 2025 René Adler - 0.1.0
- Initial packaging.