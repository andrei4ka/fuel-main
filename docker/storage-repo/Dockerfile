#Link /var/www/nailgun/{centos,ubuntu,redhat} to /repo/{centos,ubuntu,redhat} on invocation
FROM busybox
RUN mkdir -p /var/www/nailgun/
VOLUME ["/var/www/nailgun/", "/etc/yum.repos.d/"]
CMD /bin/echo storage/repo I am a data-only container for Fuel && ln -s /repo/* /var/www/nailgun/
