/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package appletaplication.token;

import appletaplication.plataform.OSValidator;
import appletaplication.utiles.Utiles;
import appletaplication.utiles.UtilesResources;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 *
 * @author JMiraballes
 */
public class HandlerToken {
    
    private ArrayList<Token> tokens;

    /**
     * Carga todos los tokens configurados en la pc del usuario. 
     * 
     */
    public HandlerToken()  {
        try{
            tokens = new ArrayList();
            String libraries = "";
            //se cargans libs
            List<String> librStr = new ArrayList<String>();
            if (OSValidator.isWindows()) {
                libraries = UtilesResources.getProperty("appletConfig.LibrariesWin");
                String[] libsarray = Utiles.splitByCaracter(libraries, ",");
                for (int i = 0; i < libsarray.length; i++){
                    //librStr.add(strarray[i]);
                    //En windows se agrega variable de entorno en caso de que la ruta no 
                    //comience con c:
                    if (!libsarray[i].startsWith("C:")){
                        librStr.add( System.getenv("programfiles") + libsarray[i]);
                    }
                    else{
                        //como comienza con C: se agrega toda la ruta.
                        librStr.add( libsarray[i]);
                    }
                }
            }
            
            if (OSValidator.isUnix()){
                libraries = UtilesResources.getProperty("appletConfig.LibrariesUni");
                String[] strarray = Utiles.splitByCaracter(libraries, ",");
                for (int i = 0; i < strarray.length; i++){
                    librStr.add(strarray[i]);
                }
            }
            //se cargans modulos 1 a 1 con cada libs
            String modulos = UtilesResources.getProperty("appletConfig.Modulos");
            String[] modarray = Utiles.splitByCaracter(modulos, ",");
            for (int i = 0; i < modarray.length; i++){
                Token token = new Token(modarray[i], librStr.get(i));
                tokens.add(token);
                if (token.isActivo()){
                    break;
                }
            }
            
            //reviso de varible entonrno smart_card
            boolean istokenactivo = false;
            if (tokens != null){
                Iterator<Token> it = tokens.iterator();
                while (it.hasNext()){
                    Token t = it.next();
                    if (t.isActivo()){
                        istokenactivo = t.isActivo();
                        break;
                    }
                }
            }
            //En caso que no exista token/tarjeta activa se consulta por la variable de entrono SmartCard.
            if (!istokenactivo){
                String dllenv = System.getenv( UtilesResources.getProperty("appletConfig.SmartCardEnviroment"));
                System.out.println("Env: " + dllenv);
                //El se asigna un nombre de modulo. Es el mismo que el de la variable de entorno configurada.
                Token token = new Token(UtilesResources.getProperty("appletConfig.SmartCardEnviroment"), dllenv);
                tokens.add(token);
            }
        } 
        catch (IOException ex) {
            Logger.getLogger(HandlerToken.class.getName()).log(Level.SEVERE, null, ex);
        }        
    } 

    public ArrayList<Token> getTokens() {
        if (tokens == null){
            tokens = new ArrayList();
        }
        return tokens;
    }

    public void setTokens(ArrayList<Token> lista) {
        this.tokens = lista;
    }
    
    /**
     * Obtiene el token activo de la lista de tokens configurados
     * en la maquina local.
     * 
     * @return 
     */
    public Token getTokenActivo(){
        
        Iterator<Token> it = getTokens().iterator();
        Token token = null;
        
        while (it.hasNext()){
            Token t = it.next();
            if (t.isActivo()){
                token = t;
                break;
            }
        }
        return token;
    }
    
    /**
     * Método que retorna true si existe un token activo en el sistema, o sea
     * que se encuentra conectado a la pc.
     * @return 
     */
    public boolean isTokenActivo(){
        boolean isActivo = false;
        
        Iterator<Token> it = getTokens().iterator();
        
        while (it.hasNext()){
            Token t = it.next();
            if (t.isActivo()){
                isActivo = true;
                break;
            }
        }
        return isActivo;
    }
    
    public void desactivarAllTokens() throws LoginException{
        Iterator<Token> it = getTokens().iterator();
        
        while (it.hasNext()){
            Token t = it.next();
            t.setActivo(false);
            if (t.isLogued()){
                t.logout();
            }
        }
    }
    
    
}
