/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package appletaplication.utiles;

import java.io.IOException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author JMiraballes
 * 
 * Clase que encapsula el mecanismo de acceso a un archivo de properties que
 * se encuentra en la la web donde se embebe el applet.
 * 
 */
public class UtilesResources {
    
    private static UtilesResources instance;
    private static String rutaProperties;
    private Properties appProperties = null;
    
    private UtilesResources() throws IOException{
        try{
            appProperties = new Properties();            
            appProperties.load(( new URL( rutaProperties )).openStream());
        }
        catch(IOException ex){
            Logger.getLogger(UtilesResources.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;            
        }
    }
    
    private static UtilesResources getInstance() throws IOException{
        if (instance == null){
            instance = new UtilesResources();
        }
        return instance;
    }
     
    public static String getProperty(String key) throws IOException{
        return getInstance().getProperties().getProperty(key);
    }
    
    private Properties getProperties(){
        return this.appProperties;
    }
    
    public static String getRutaProperties(){
        return rutaProperties;
    }
    
    public static void setRutaProperties( String ruta ){
        rutaProperties = ruta;
    }    
    
    
}
