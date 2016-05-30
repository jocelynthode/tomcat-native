

# Tomcat Native 2

Fork of the apache Tomcat Native project focused on keeping the OpenSSL engine while removing the APR dependency.
This project is also meant to be compatible with Undertow.

## Build Tomcat Native 2
First build the jar file used in Tomcat and Undertow:
`ant jar`

Then build the native shared object:
* `cd native`
* `./buildconf && ./configure && make` The warning concerning the failure to install tomcat native 2 is not important.

## How to use in Tomcat
* Set the TCN2 shell variable to the absolute path of the Tomcat Native repository : `TCN2=path/to/tomcat-native`
* Clone our fork of Tomcat and cd into it: `git clone https://github.com/jocelynthode/tomcat.git && cd tomcat && git checkout TCN2_UNDERCAT`
* Set the tcn2.jar property in the build.properties: `echo  "tcn2.jar=$TCN2/dist/tomcat-native-1.2.5.jar" >> build.properties`
* Build tomcat: `ant`

### Run server with example config
* Apply sample config with OpenSSL, H2 and SNI: `git cherry-pick -n origin/tmp_conf`
* Add tomcat-native paths to startup scripts:
```
echo CLASSPATH="$TCN2/dist/tomcat-native-1.2.5.jar" >> bin/setenv.sh
echo export JAVA_TOOL_OPTIONS="-Djava.library.path=$TCN2/native/.libs/" >> bin/setenv.sh
```

* Run ant to copy some config files: `ant`
* Copy keys and certificates: `rsync -rv conf/ output/build/conf/`
* Run server: `output/build/catalina.sh run`

### Run tests
* Set test.sslImplementation property: 
```
echo test.sslImplementation=org.apache.tomcat.util.net.openssl.OpenSSLImplementation >> build.properties`
```
* Create symlinks to tomcat-native shared objects: 
```
mkdir -p bin/native && ln -s "$TCN2"/native/.libs/* bin/native/`
```
* Run tests: `LANG=C ant test`

Quick and ugly hack to only run tests related to ssl:
```
find test/org/apache/tomcat/util/net/ -iname "test*.java" -a ! -iname 'tester*.java' | sed s@/@\.@g | sed 's/^test.//g' | sed 's/.java$//g' | xargs -I%s env LANG=C ant test-nio -Dtest.entry=%s
```

## How to use in Undertow
* Set the TCN2 shell variable to the absolute path of the Tomcat Native repository : `TCN2=path/to/tomcat-native`
* Clone our fork of Undertow and cd into it: `git clone https://github.com/jocelynthode/undertow.git && cd undertow && git checkout TCN2_UNDERCAT`
* Install tcn2 jar into maven local repository: `./deps.sh "$TCN2"`
* Build Undertow: `mvn package -DskipTests -Dcheckstyle.skip`

Now run the HTTP2 OpenSSL Server example:
```
cd examples/target
java "-Djava.library.path=$TCN2/native/.libs" -Xbootclasspath/p:alpn.jar -cp "undertow-examples.jar:$TCN2/dist/tomcat-native-1.2.5.jar" io.undertow.examples.openssl.OpenSSLServer
```

