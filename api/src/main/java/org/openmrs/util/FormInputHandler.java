/**
 * 
 * A utility class for handling security related input sanitization to mitigate
 * client side attacks of XSS and XML injection
 * @author http://github.com/subodh-dharma
 * @author http://github.com/rushigerrard
 * @version 0.1
 * @since 2016-11-11
 * 
 */

package org.openmrs.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class FormInputHandler {

	
	private static final Log log = LogFactory.getLog(FormInputHandler.class);
	
	/**
	 * 
	 * @param input Input string of which we need to check if the input String contains script tags
	 * @param varName Name of variable for which check is performed.  
	 * @return status true - if contains script tags false - if string is clean.
	 */
	
	public boolean containsScriptTags(String input, String varName){
				
		String pattern = "(?i)<(/?script[^>]*)>";
	    
	    Pattern p = Pattern.compile(pattern);
	    Matcher m = p.matcher(input);
	    if(m.find()){
	    	return true;	      
	    }else
	    {
	    	log.info("A possible security incident has occured - XSS injection");
	    	log.debug("XSS ATTACK OCCURED, AT INPUT "+varName+" , ACTUAL INPUT STRING : "+input );
	 		return false;   	
	    }
		
		
	}
}
