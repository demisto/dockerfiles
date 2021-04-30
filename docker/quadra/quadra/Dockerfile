FROM openjdk:13

# configure paths for quadra and logs
USER root
RUN mkdir -p /usr/local/titaniam && \
    mkdir -p /usr/share/titaniam
    
COPY files/license /usr/share/titaniam
COPY files/master.seed /usr/share/titaniam

COPY files/server-1.0-SNAPSHOT.jar /usr/local/titaniam/server-1.0-SNAPSHOT.jar
COPY files/application.properties /usr/local/titaniam/application.properties
COPY files/master.seed /usr/local/titaniam/master.seed
COPY files/license /usr/local/titaniam/license
COPY files/logback.xml /usr/local/titaniam/logback.xml

WORKDIR /usr/local/titaniam/

# Create a user group and user 'titaniam'
RUN groupadd -r titaniam && useradd --no-log-init -r -g titaniam titaniam

# Chown all the files to the titaniam:titaniam user.
RUN chown -R titaniam:titaniam /usr/local/titaniam && \
    chown -R titaniam:titaniam /usr/share/titaniam

# Switch to 'titaniam' user
USER titaniam

CMD ["java" ,"-Dlog4j.debug", "-Dlogging.config=logback.xml", "-jar", "server-1.0-SNAPSHOT.jar", "--spring.config.location=application.properties"]
