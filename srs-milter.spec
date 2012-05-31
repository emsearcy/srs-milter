Summary:        Sendmail milter for SRS
Name:           srs-milter
Version: 0.0.1
Release: 1
License:        GPL
Group:          System Environment/Daemons
URL:            http://kmlinux.fjfi.cvut.cz/~vokacpet/activities/srs-milter

Source0:        http://kmlinux.fjfi.cvut.cz/~vokacpet/activities/srs-milter/%{name}-%{version}.tar.gz
#Source1:        srs-milter.init
#Source2:        srs-milter.sysconfig
Patch01:        srs-milter-0.0.1-libdir.patch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  sendmail-devel
# FIXME: openssl 0.9.8 workround
Autoreq: 0
Requires:       sendmail

Requires(pre):  /usr/sbin/useradd
Requires(post): /sbin/chkconfig
Requires(post): /sbin/service
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service

%description
The srs-milter package is an implementation of the SRS standard
that tries to fix problems caused by SPF in case of forwarded mail

%prep
%setup -q
#%patch01 -p1 -b .libdir

%build
%{__make} %{?_smp_mflags} -C src

%install
%{__rm} -rf %{buildroot}

#%{__make} %{?_smp_mflags} -C src install

%{__install} -D -m0755 srs-milter.init %{buildroot}%{_initrddir}/srs-milter
%{__install} -D -m0644 srs-milter.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/srs-milter
%{__install} -d -m0700 %{buildroot}%{_localstatedir}/run/srs-milter
#%{__install} -D -m0664 srs-milter/srs-milter.8 %{buildroot}%{_mandir}/man8/srs-milter.8
#%{__install} -D -m0755 obj.`uname -s`.`uname -r`.`uname -p`/srs-milter/srs-milter %{buildroot}%{_sbindir}/srs-milter
%{__install} -D -m0755 src/srs-filter %{buildroot}%{_sbindir}/srs-filter
#%{__strip} %{buildroot}%{_sbindir}/srs-filter

%pre
/usr/sbin/useradd -r -s /sbin/nologin -d %{_localstatedir}/run/srs-milter \
	-c "SRS Milter" srs-milt &>/dev/null || :

%post
/sbin/chkconfig --add srs-milter || :

%preun
if [ $1 -eq 0 ]; then
    /sbin/service srs-milter stop &>/dev/null || :
    /sbin/chkconfig --del srs-milter || :
fi

%postun
/sbin/service srs-milter condrestart &>/dev/null || :

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc README
#%{_mandir}/man8/srs-milter.8*
%config(noreplace) %{_sysconfdir}/sysconfig/srs-milter
%{_initrddir}/srs-milter
%{_sbindir}/srs-filter
%dir %attr(-,srs-milt,root) %{_localstatedir}/run/srs-milter

%changelog
* Mon Jul  4 2011 Petr Vokac <vokac@kmlinux.fjfi.cvut.cz> - 0.0.1-1
- Initial package.
