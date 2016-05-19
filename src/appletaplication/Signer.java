/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package appletaplication;

/**
 *
 * @author JMiraballes
 * Clase de para probar los distintos tipos de firma. De esta forma se logra
 * probar rápidamente las diferentes fuentes de firma.
 * 
 */
public class Signer {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        JavaApplet jp = new JavaApplet();
        String firma = jp.firmarDirecto("true", 
                "http://localhost:9000/ISCert/resources/imm/applet.properties",
                    "texto prueba", 
                        "Usuario Uno", 
                            "54325432532");
        
        System.out.println("Firma realizada exitosamente: " + firma);
        //String isTrustedx, String ruta, String hashParam, String usuParam, String passParam
    }
}
