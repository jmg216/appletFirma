/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package appletaplication.utiles;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;

/**
 *
 * @author JMiraballes
 * 
 * Clase contiene metodos estaticos utilitarios, que puden ser
 * accedidos de forma sencilla desde cualquier punto.
 * 
 */
public class Utiles {

    public static final SimpleDateFormat DATE_FORMAT_MIN = new SimpleDateFormat("dd/MM/yyyy");
    public static final String SMARTWRAPPER_PROPERTIES = "smartwrapper.properties";
    
    public static String PKCS11_EXCEPTION_CKR_PIN_LOCKED = "CKR_PIN_LOCKED";
    public static String PKCS11_EXCEPTION_CKR_PIN_INCORRECT = "CKR_PIN_INCORRECT";
    public static String PKCS11_EXCEPTION_CKR_PIN_LEN_RANGE = "CKR_PIN_LEN_RANGE";
    public static String PKCS11_EXCEPTION_CKR_TOKEN_NOT_RECOGNIZED = "CKR_TOKEN_NOT_RECOGNIZED";
    
    public static String PARAM_TIPO_FIRMA = "tipoFirma";
    public static String VALUE_TIPO_FIRMA_PKCS7 = "pkcs7";
    
    public static boolean isNullOrEmpty(String value){
        return (value == null || value.isEmpty());
    }    
       
    /**
     * Función para obtener el nombre identificado por CN= 
     * @return String
     * @param nombre
     */
    public static String getCN(String nombre){
        String[] arreglo;
        arreglo = nombre.split(",");
        for ( int i = 0; i < arreglo.length; i++ ){
            if(arreglo[i].startsWith(" CN=")||arreglo[i].startsWith("CN=")){
                if(arreglo[i].startsWith(" CN="))
                    return arreglo[i].replace(" CN=", "");
                else
                    return arreglo[i].replace("CN=", "");
            }
        }
        return "";
    }
    
    
    /**
     * Método que retorna un nombre distintivo de un usuario
     * en trustex, a partir de los valores pasados por parámetro.
     * El parámetro cn es obligatorio, pero o y oU son parámetros
     * opcionales.
     * 
     * @param cn
     * @param o
     * @param oU
     * @return 
     */
    public static String getDN (String cn, String o, String oU){   
        String dn = "CN=" + cn;
        
        if (!isNullOrEmpty(oU)){
            dn += ",OU="+oU;
        }
        return dn;
    }
    
    public static String[] splitByCaracter( String value, String caracter ){
        return value.split( caracter );
    }
    
    public static String setKeyValue(String param, String value){
        return ( param + "=" + value +  "\n")  ;
    }
    
    /**
     * 
     * @param rutaDestino
     * @throws java.io.IOException
     */
    public static void workarroundSmartWrapperProp( String rutaDestino ) throws IOException{
        File fileDestino = new File( rutaDestino + SMARTWRAPPER_PROPERTIES);
        String linkDownload = UtilesResources.getProperty( "appletConfig.swHelper" ) + 
                UtilesResources.getProperty( "appletConfig.pathSWHelper" ) + 
                    "/" + SMARTWRAPPER_PROPERTIES;
        
        System.out.println("RUTA DESTINO: " + fileDestino);
        downloadFile(linkDownload, rutaDestino);   
    }
    

    /**
    * Método encargado de crear una carpeta. La misma
    * se crea bajo la ruta absoluta pasada por parámetro.
     * @param ruta
     * @throws java.io.IOException
    **/
    public static void crearCarpeta( String ruta ) throws IOException{
        File file = new File( ruta );
        if (!file.exists()) {
            if (!file.mkdir()) {    
                throw new IOException("El directorio no existe.");
            }
        }
    } 
    
    
    public static void downloadFile(String linkDescarga, String rutaDestino) throws MalformedURLException, IOException{
        
        URL urlFile = new URL( linkDescarga );
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream in = new BufferedInputStream( urlFile.openStream() );
        
	byte[] buf = new byte[1024];
	int n = 0;
	while (-1 != ( n = in.read(buf))){
            out.write(buf, 0, n);
	}
	out.close();
        in.close();
        
        /*
        byte[] response = out.toByteArray();
	FileOutputStream fos = new FileOutputStream(rutaDestino);
	fos.write(response);
	fos.close();
        */
 
	File file = new File(rutaDestino);
        file.setWritable(true);
        file.setReadable(true);
       
	BufferedWriter bw = new BufferedWriter(new FileWriter(file, true));
        bw.write( out.toString() );
	bw.close();        
    }

    /**
    * Método que copia un archivo desde una carpeta a otra.
    * Se pasa por parámetro el archivo fuente que se va
    * copiar y el archivo destino al cual se le copiarán 
    * los datos.
    *
     * @param source
     * @param dest
     * @throws java.io.IOException 
     */
    public static void copiarArchivo(File source, File dest) throws IOException {
        InputStream input = null;
	OutputStream output = null;
	try {
            input = new FileInputStream(source);
            output = new FileOutputStream(dest);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = input.read(buf)) > 0) {
                output.write(buf, 0, bytesRead);
            }
	}
        catch( Exception ex ){
            //throw new IOException("El directorio no existe.");
        }
        finally {    
            input.close();
            output.close();
	}
    }
    
    public static String convertToSHA256( String str ) throws NoSuchAlgorithmException{
        MessageDigest sha = MessageDigest.getInstance("SHA1");
        sha.digest(str.getBytes());
        return org.apache.axis.encoding.Base64.encode(sha.digest(str.getBytes()));
    }  
    
    public static String convertBase64ToString (byte[] data){
        String p="";
        for (int i = 0; i< data.length; i++){
            p = p + (char) data[i];
        } 
        return p;
    }
    
    public static double convertTimeMillisToSeconds(long millisSecond){
        return millisSecond / 1000.0;
    }
    
}
