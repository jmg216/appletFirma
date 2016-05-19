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
            List<String> librStr = new ArrayList<String>();
            if (OSValidator.isWindows()) {
                libraries = UtilesResources.getProperty("appletConfig.LibrariesWin");
                String[] strarray = Utiles.splitByCaracter(libraries, ",");
                for (int i = 0; i < strarray.length; i++){
                    //en windows concatenar programs 
                    librStr.add( System.getenv("programfiles") + strarray[i]);
                }
            }        
            if (OSValidator.isUnix()){
                libraries = UtilesResources.getProperty("appletConfig.LibrariesUni");
                String[] strarray = Utiles.splitByCaracter(libraries, ",");
                for (int i = 0; i < strarray.length; i++){
                    librStr.add(strarray[i]);
                }
            }
            System.out.println("Env: " + UtilesResources.getProperty("appletConfig.SmartCardEnviroment"));
            librStr.add( System.getenv( UtilesResources.getProperty("appletConfig.SmartCardEnviroment")));
            
            String modulo = UtilesResources.getProperty("appletConfig.Modulos");
            for (String str : librStr){
                Token token = new Token(modulo, str);
                tokens.add(token);
                if (token.isActivo()){
                    break;
                }
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
