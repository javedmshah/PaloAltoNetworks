/**
 * Created by javedshah on 3/15/14.
 */
package org.forgerock.openam.authentication.plugins.paloaltonetworks;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;
import com.sun.identity.shared.debug.Debug;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import javax.xml.bind.annotation.XmlElement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.dom.DOMSource;
import org.apache.commons.httpclient.methods.multipart.*;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.params.*;
import org.apache.commons.httpclient.protocol.*;
import org.w3c.dom.Attr;
import org.w3c.dom.CDATASection;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * JSHAH:A ton of cleanup needs to happen in this file.
 * This is interim code demonstrating UserId API with PAN firewall
 */

public class PAFirewallPAP implements AMPostAuthProcessInterface {
    private final static String DEBUG_FILE = "PAFirewallPAP";

    //protected Debug debug = Debug.getInstance(DEBUG_FILE);

    @SuppressWarnings("deprecation")
	public void onLoginSuccess(Map arg0, HttpServletRequest request, HttpServletResponse res, SSOToken token)
    	    throws AuthenticationException {

    	System.out.println("******* INSIDE onLoginSuccess ***********");
    	try {
    		//String uid = (String) arg0.get("IDToken1");
            String uid = token.getProperty("userid");
    		System.out.println("uid : "+uid);
	        if(uid != null) {
	        	
	        	String filePath = "/tmp/useridLoginMappingFile.xml";
	        	String command = "login";
	        	createXMLMessageFile(command, uid, filePath);
	        	
	        	String url = "http://10.0.61.1/api/?type=user-id&action=set&key=<your-api-key>";
	            File file = new File(filePath);

	            PostMethod method = new PostMethod( url );
	            HttpClient httpclient = new HttpClient();
	            //httpclient.getParams().setParameter(CoreProtocolPNames.PROTOCOL_VERSION, HttpVersion.HTTP_1_1);
	     
	            Part[] parts = { new StringPart("filename", "useridLoginMappingFile.xml"), new FilePart( "file", file ) };
	            method.setRequestEntity( new MultipartRequestEntity( parts, method.getParams() ) );
	        
	            int returnCode = httpclient.executeMethod( method );
	            if(returnCode == HttpStatus.SC_NOT_IMPLEMENTED) {
	            	System.err.println("The Post method is not implemented by this URI");
	            	method.getResponseBodyAsString();
	            } else {
	                    BufferedReader br = new BufferedReader(new InputStreamReader(method.getResponseBodyAsStream()));
	                    String readLine;
	                    while(((readLine = br.readLine()) != null)) {
	            	        System.out.println(readLine);
	                    }
		    	}
		    	method.releaseConnection();
	        	
	        } else {
	        	System.out.println("NULL uid, skipping REST call");
	        }
	        
    	} catch (Exception ex) {
    		System.out.println("Exception calling PA Firewall web service: "+ex.getMessage());
    		ex.printStackTrace();
    	}
    }
    
    
    /*
     * 
    <uid-message> 
    	<payload> 
    		<login>
				<entry name="amadmin" ip="10.0.60.2" startport="8080" endport="8081" blocksize="2"/> 
			</login>
		</payload> 
		<type>update</type> 
		<version>1.0</version>
	</uid-message>


	<uid-message> 
		<payload>
			<logout>
				<entry user="amadmin" ip="10.0.61.2"  startport="8080" endport="8081" blocksize="2"/>
			</logout> 
		</payload> 
		<type>update</type> 
		<version>1.0</version>
	</uid-message>

     * 
     */
    private void createXMLMessageFile(String command, String uid, String filePath) throws Exception {
    	DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		Element uidmsg = doc.createElement("uid-message");
		doc.appendChild(uidmsg);
		
		Element payload = doc.createElement("payload");
		uidmsg.appendChild(payload);
		Element type = doc.createElement("type");
		type.setTextContent("update");
		uidmsg.appendChild(type);
		Element version = doc.createElement("version");
		version.setTextContent("1.0");
		uidmsg.appendChild(version);
		
		Element login = doc.createElement(command);
		payload.appendChild(login);
		
		Element entry = doc.createElement("entry");
		entry.setAttribute("name", uid);
		/*
		 * JSHAH
		 * Need to put this in a property file
		 */
		entry.setAttribute("ip", "10.0.60.2");
		entry.setAttribute("startport", "8080");
		entry.setAttribute("endport", "8081");
		entry.setAttribute("blocksize", "2");
		login.appendChild(entry);
		
		// create a new file
        TransformerFactory tfac = TransformerFactory.newInstance();
        Transformer tmer = tfac.newTransformer();
        DOMSource src = new DOMSource(doc);
        StreamResult res = new StreamResult(new File(filePath));
        StreamResult res1 = new StreamResult(System.out);
		tmer.transform(src, res);
		System.out.println("file saved!");
    }
    
    
    public static String computeSha1OfString(final String message) 
    	    throws UnsupportedOperationException, NullPointerException {
    	        try {
    	               return computeSha1OfByteArray(message.getBytes(("UTF-8")));
    	        } catch (UnsupportedEncodingException ex) {
    	                throw new UnsupportedOperationException(ex);
    	        }
    	}

	private static String computeSha1OfByteArray(final byte[] message)
	    throws UnsupportedOperationException {
	        try {
	            MessageDigest md = MessageDigest.getInstance("SHA-1");
	            md.update(message);
	            byte[] res = md.digest();
	            return toHexString(res);
	        } catch (NoSuchAlgorithmException ex) {
	            throw new UnsupportedOperationException(ex);
       }
	}
    private static String toHexString(byte[] bytes) {
    	char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j*2] = hexArray[v >>> 4];
            hexChars[j*2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
	}

	/**
     * Method used to print the SOAP Response
     */
    private static void printSOAPResponse(SOAPMessage soapResponse) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        Source sourceContent = soapResponse.getSOAPPart().getContent();
        System.out.print("\nResponse SOAP Message = ");
        StreamResult result = new StreamResult(System.out);
        transformer.transform(sourceContent, result);
    }

    public void onLoginFailure(Map arg0, HttpServletRequest arg1, HttpServletResponse arg2)
            throws AuthenticationException {
        // not used
    }

    public void onLogout(HttpServletRequest arg0, HttpServletResponse response, SSOToken token)
            throws AuthenticationException {
    	System.out.println("******* INSIDE onLogout *********** "+token.toString());
    	try {
    		String uid = null;
    		String[] array1 = token.getPrincipal().getName().split("=");
    		if(array1.length>1) {
    			System.out.println("array1[0] : "+array1[0]);
    			System.out.println("array1[1] : "+array1[1]);
    			String[] array2 = array1[1].split(",");
    			if(array2.length!=0) {
    				System.out.println("array2[0] : "+array2[0]);
        			uid = array2[0];
    				System.out.println("uid in inner loop : "+uid);
    			} else {
    				uid = null;
    				System.out.println("uid in inner loop is null");
    			}
    		} else {
    			System.out.println("uid in outer loop is null!");
    		}
    		System.out.println("uid : "+uid);
	        if(uid != null) {
	        	
	        	String filePath = "/tmp/useridLogoutMappingFile.xml";
	        	String command = "logout";
	        	createXMLMessageFile(command, uid, filePath);
	        	
	        	String url = "http://10.0.61.1/api/?type=user-id&action=set&key=<your-api-key>";
	            File file = new File(filePath);

	            PostMethod method = new PostMethod( url );
	            HttpClient httpclient = new HttpClient();
	            //httpclient.getParams().setParameter(CoreProtocolPNames.PROTOCOL_VERSION, HttpVersion.HTTP_1_1);
	     
	            Part[] parts = { new StringPart("filename", "useridLogoutMappingFile.xml"), new FilePart( "file", file ) };
	            method.setRequestEntity( new MultipartRequestEntity( parts, method.getParams() ) );
	        
	            int returnCode = httpclient.executeMethod( method );
	            if(returnCode == HttpStatus.SC_NOT_IMPLEMENTED) {
	            	System.err.println("The Post method is not implemented by this URI");
	            	method.getResponseBodyAsString();
	            } else {
	                    BufferedReader br = new BufferedReader(new InputStreamReader(method.getResponseBodyAsStream()));
	                    String readLine;
	                    while(((readLine = br.readLine()) != null)) {
	            	        System.out.println(readLine);
	                    }
		    	}
		    	method.releaseConnection();
	        	
	        } else {
	        	System.out.println("NULL uid, skipping REST call");
	        }
	        
    	} catch (Exception ex) {
    		System.out.println("Exception calling PA Firewall web service: "+ex.getMessage());
    		ex.printStackTrace();
    	}
    }
}
