# REST API Java Examples
This is Adhara's repository for examples, sample code written in Java that demonstrates in a simple way how to use our REST API.

* getAccount
* getInterface
* pricePolling
* priceStreaming
* orderPolling
* orderStreaming
* positionPolling
* positionStreaming
* setOrder
* cancelOrder
* modifyOrder
* getHistoricalPrice
* authentication

### Pre-requisites:
You need to install a Java Development Kit and set it up so they are able to compile and execute using 'javac' and 'java' from a terminal window. 

### How to:

**1. Clone this repository to the location of your choice** 

The repository contains all the examples listed above together with the classes needed. 

**2. Modify config.properties file with your settings** 

```
domain=http://actfx.adhara.io
user=demo
password=demo
```

**3. Modify the following lines in the Java program you would like to run.** 

From here on we will assume it is priceStreaming.java.
```
hftrequest = new hftRequest(user, token, Arrays.asList("EUR/USD", "GBP/USD"), null, "tob", 1, interval);
```

In case you want to disable ssl protocol, change the following line:
```
private static final boolean ssl = true;
```

**4. Run the examples using the '.sh' script such as this one:**
```javascript
$ export JARS=lib/commons-codec-1.9.jar:lib/commons-logging-1.2.jar:lib/fluent-hc-4.5.jar:lib/httpclient-4.5.jar:lib/httpclient-cache-4.5.jar:lib/httpclient-win-4.5.jar:lib/httpcore-4.4.1.jar:lib/httpmime-4.5.jar:lib/jackson-all-1.9.9.jar:lib/jna-4.1.0.jar:lib/jna-platform-4.1.0.jar

$ javac -cp $JARS src/priceStreaming.java
```

**5. Execute the sample.**
```javascript
$ export JARS=lib/commons-codec-1.9.jar:lib/commons-logging-1.2.jar:lib/fluent-hc-4.5.jar:lib/httpclient-4.5.jar:lib/httpclient-cache-4.5.jar:lib/httpclient-win-4.5.jar:lib/httpcore-4.4.1.jar:lib/httpmime-4.5.jar:lib/jackson-all-1.9.9.jar:lib/jna-4.1.0.jar:lib/jna-platform-4.1.0.jar

$ java  -cp .:./src:$JARS priceStreaming

Response timestamp: 1441712414.982956 Contents:
Security: EUR/USD Price: 1.11618 Side: ask Liquidity: 1000000
Security: EUR/USD Price: 1.11613 Side: bid Liquidity: 1000000
Response timestamp: 1441712415.983567 Contents:
Heartbeat!
Response timestamp: 1441712416.194543 Contents:
Security: EUR/USD Price: 1.11618 Side: ask Liquidity: 1000000
Security: EUR/USD Price: 1.11614 Side: bid Liquidity: 500000
```


