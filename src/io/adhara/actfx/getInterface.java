package io.adhara.actfx;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;

// Note: Following libraries are required:
//
// 1) 'jackson-all-xxx.jar'       with MAVEN dependency: groupId 'org.codehaus.jackson', artifactId 'jackson' and version 1.9.9 
//                         or download from main project at 'http://www.java2s.com/Code/Jar/j/Downloadjacksonall199jar.htm'
//
// 2) 'httpclient-xxx.jar' with MAVEN dependency: groupId 'org.apache.httpcomponents', artifactId 'fluent-hc' and version 4.5
//                         or download from main project at 'https://hc.apache.org'

public class getInterface {

	private static final boolean ssl = true;
	private static final String URL = "/getInterface";
	private static String domain;
	//private static String url_stream;
	private static String url_polling;
	private static String url_challenge;
	private static String url_token;
	private static String user;
	private static String password;
	private static String authentication_port;
	private static String request_port;
	private static String ssl_cert;
	private static String challenge;
	private static String token;
	//private static int interval;
	
	public static class hftRequest {
		public getAuthorizationChallengeRequest getAuthorizationChallenge;
		public getAuthorizationTokenRequest getAuthorizationToken;
		public getInterfaceRequest  getInterface;
		
		public hftRequest() {
			this.getAuthorizationChallenge = new getAuthorizationChallengeRequest(user); 
		}
	}
	
	public static class hftResponse{
		public getAuthorizationChallengeResponse getAuthorizationChallengeResponse;
        public getAuthorizationTokenResponse getAuthorizationTokenResponse;
        public getInterfaceResponse getInterfaceResponse;
    }
	
	public static class getAuthorizationChallengeRequest {
        public String        user;
        
        public getAuthorizationChallengeRequest( String user ) {
        	this.user = user;
        }
    }
	
	public static class getAuthorizationChallengeResponse {
        public String        challenge;
        public String        timestamp;
    }
	
	public static class getAuthorizationTokenRequest {
        public String        user;
        public String        challengeresp;
        
        public getAuthorizationTokenRequest( String user, String challengeresp ) {
        	this.user = user;
        	this.challengeresp = challengeresp;
        }
    }
	
	public static class getAuthorizationTokenResponse {
        public String        token;
        public String        timestamp;
    }

	public static class getInterfaceRequest {
        public String        user;
        public String        token;

        public getInterfaceRequest( String user, String token ) {
            this.user = user;
            this.token = token;
        }
    }

    public static class getInterfaceResponse {
    	public List<tinterfaceTick> tinterface;
        public String               timestamp;
    }
	
    public static class tinterfaceTick {
        public String        name;
        public String        description;
        public String        account;
        public String        commissions;
    }

    public static void main(String[] args) throws IOException, DecoderException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
    	
    	// get properties from file
    	getProperties();
    	
    	final ObjectMapper mapper = new ObjectMapper();
		List<Header> headers = new ArrayList<Header>();
		headers.add( new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/json") );
		headers.add( new BasicHeader(HttpHeaders.ACCEPT, "application/json") );
		CloseableHttpClient client=null;
		if (ssl){
			// get certificate
	    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    	URL url = new URL(ssl_cert);
	    	URLConnection connection = url.openConnection();
	    	InputStream in = connection.getInputStream();
	    	Certificate cert = cf.generateCertificate(in);
	    	//System.out.println("Cert:\n===================\n" + cert.getPublicKey().toString() + "\n");
	    	in.close();
	    	TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
	    	KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	    	ks.load(null); // You don't need the KeyStore instance to come from a file.
	    	ks.setCertificateEntry("cert", cert);
	    	tmf.init(ks);
	   		SSLContext sslContext = SSLContext.getInstance("TLS");
	    	sslContext.init(null, tmf.getTrustManagers(), null);
	    	client = HttpClients.custom().setSSLContext(sslContext).setDefaultHeaders(headers).build();
		}
		else{
			client = HttpClients.custom().setDefaultHeaders(headers).build();
		}
    	
    	// Create a custom response handler
        ResponseHandler<String> responseHandler = new ResponseHandler<String>() {
        	
            @Override
            public String handleResponse(final HttpResponse httpresponse) throws ClientProtocolException, IOException {
                int status = httpresponse.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    HttpEntity entity = httpresponse.getEntity();
                    
                    // --------------------------------------------------------------
                    // Wait for response from server (polling)
                    // --------------------------------------------------------------

                    try {
                    	InputStreamReader stream = new InputStreamReader(entity.getContent());
                    	BufferedReader bufferedReader = new BufferedReader(stream);
                        String line = null;
                        
                        while ((line = bufferedReader.readLine()) != null) {
                        	hftResponse response = mapper.readValue(line, hftResponse.class);
                        	
                        	if (response.getAuthorizationChallengeResponse != null){
                        		challenge = response.getAuthorizationChallengeResponse.challenge;
                        		return null;
                        	}
                        	if (response.getAuthorizationTokenResponse != null){
                        		token = response.getAuthorizationTokenResponse.token;
                        		return null;
                        	}
                        	if (response.getInterfaceResponse != null){
                        		if (response.getInterfaceResponse.tinterface!= null){
									for (tinterfaceTick tick : response.getInterfaceResponse.tinterface){
										System.out.println("Name: " + tick.name + " Account: " + tick.account + " Commissions: " + tick.commissions);
                                    }
								}
                        	}
                        }
                    }
                    catch (IOException e) { e.printStackTrace(); }
                    catch (Exception e) { e.printStackTrace(); }
                    
                    return null;
                    
                } else {
                    throw new ClientProtocolException("Unexpected response status: " + status);
                }
            }
        };
        
        try {
        	hftRequest hftrequest;
        	StringEntity request;
        	HttpPost httpRequest;
        	
        	// get challenge
        	hftrequest = new hftRequest();
        	hftrequest.getAuthorizationChallenge = new getAuthorizationChallengeRequest(user);
        	mapper.setSerializationInclusion(Inclusion.NON_NULL);
			mapper.configure(DeserializationConfig.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
			request = new StringEntity(mapper.writeValueAsString(hftrequest));
			System.out.println(mapper.writeValueAsString(hftrequest));
			httpRequest = new HttpPost(domain + ":" + authentication_port + url_challenge);
			httpRequest.setEntity(request);
			client.execute(httpRequest, responseHandler);
			
			// create challenge response
			byte[] a = Hex.decodeHex(challenge.toCharArray());
			byte[] b = password.getBytes();
			byte[] c = new byte[a.length + b.length];
			System.arraycopy(a, 0, c, 0, a.length);
			System.arraycopy(b, 0, c, a.length, b.length);
			byte[] d = DigestUtils.sha1(c);
			String challengeresp = Hex.encodeHexString(d);
			
			// get token with challenge response
			hftrequest.getAuthorizationToken = new getAuthorizationTokenRequest(user, challengeresp);
			mapper.setSerializationInclusion(Inclusion.NON_NULL);
			mapper.configure(DeserializationConfig.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
			request = new StringEntity(mapper.writeValueAsString(hftrequest));
			System.out.println(mapper.writeValueAsString(hftrequest));
			httpRequest = new HttpPost(domain + ":" + authentication_port + url_token);
			httpRequest.setEntity(request);
			client.execute(httpRequest, responseHandler);
        	
			// -----------------------------------------
	        // Prepare and send a getInterface request
	        // -----------------------------------------
			hftrequest.getInterface = new getInterfaceRequest(user, token);
			mapper.setSerializationInclusion(Inclusion.NON_NULL);
			mapper.configure(DeserializationConfig.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
			request = new StringEntity(mapper.writeValueAsString(hftrequest));
			System.out.println(mapper.writeValueAsString(hftrequest));
			httpRequest = new HttpPost(domain + ":" + request_port + url_polling + URL);
			httpRequest.setEntity(request);
			client.execute(httpRequest, responseHandler);
		} finally {
			client.close();
		}

	}
    
    public static void getProperties(){
    	Properties prop = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream("config.properties");
			prop.load(input);
			//url_stream = prop.getProperty("url-stream");
			url_polling = prop.getProperty("url-polling");
			url_challenge = prop.getProperty("url-challenge");
			url_token = prop.getProperty("url-token");
			user = prop.getProperty("user");
			password = prop.getProperty("password");
			//interval = Integer.parseInt(prop.getProperty("interval"));
			if (ssl){
				domain = prop.getProperty("ssl-domain");
				authentication_port = prop.getProperty("ssl-authentication-port");
				request_port = prop.getProperty("ssl-request-port");
				ssl_cert = prop.getProperty("ssl-cert");
			}
			else{
				domain = prop.getProperty("domain");
				authentication_port = prop.getProperty("authentication-port");
				request_port = prop.getProperty("request-port");
			}
		}
		catch (IOException ex) {
			ex.printStackTrace();
		}
		finally {
			if (input != null) {
				try {
					input.close();
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
    }

	public getInterface() {
		super();
	}

}

