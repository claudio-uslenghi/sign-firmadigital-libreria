/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.rubrica.sign;

import io.rubrica.certificate.CertEcUtils;
import static io.rubrica.certificate.CertUtils.seleccionarAlias;
import io.rubrica.certificate.Certificado;
import io.rubrica.exceptions.InvalidFormatException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;

import io.rubrica.exceptions.SignatureVerificationException;
import io.rubrica.keystore.FileKeyStoreProvider;
import io.rubrica.keystore.KeyStoreProvider;
import io.rubrica.keystore.KeyStoreProviderFactory;
import io.rubrica.sign.cms.VerificadorCMS;
import io.rubrica.sign.pdf.PDFSigner;
import io.rubrica.sign.pdf.PdfUtil;
import io.rubrica.utils.Utils;
import io.rubrica.utils.UtilsCrlOcsp;
import io.rubrica.validaciones.Documento;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mfernandez
 */
public class Main {

    // La fecha actual en formato ISO-8601 (2017-08-27T17:54:43.562-05:00)
    private static final String FECHA_HORA = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

    // ARCHIVO
    private static final String ARCHIVO = "/home/mfernandez/Firmas/SecurityData/certificados prueba 2018/pruebac/PRUEBAC MISAEL VLADIMIR.p12";
    private static final String PASSWORD = "1234";

    private static final String FILE_PDF = "/home/mfernandez/Descargas/CIUDADANO-CIU-2018-11-TEMP-signed_1_1_1_EDITADA-signed.pdf";

    public static void main(String args[]) throws KeyStoreException, Exception {
//        firmarArchivo();
//        verificarPDF();
        validarCertificado();
//        verificarP7M();
    }

    private static void firmarArchivo() throws IOException, KeyStoreException, Exception {
        //QR
        //SUPERIOR IZQUIERDA
        String llx = "10";
        String lly = "830";
        //INFERIOR IZQUIERDA
        //String llx = "100";
        //String lly = "91";
        //INFERIOR DERECHA
        //String llx = "419";
        //String lly = "91";
        //INFERIOR CENTRADO
        //String llx = "260";
        //String lly = "91";
        //QR
        //SUPERIOR IZQUIERDA
        //String llx = "10";
        //String lly = "830";
        //String urx = String.valueOf(Integer.parseInt(llx) + 110);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);
        //INFERIOR CENTRADO
        //String llx = "190";
        //String lly = "85";
        //String urx = String.valueOf(Integer.parseInt(llx) + 260);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);
        //INFERIOR CENTRADO (ancho pie pagina)
        //String llx = "100";
        //String lly = "80";&
        //String urx = String.valueOf(Integer.parseInt(llx) + 430);
        //String ury = String.valueOf(Integer.parseInt(lly) - 25);
        //INFERIOR DERECHA
        //String llx = "10";
        //String lly = "85";
        //String urx = String.valueOf(Integer.parseInt(llx) + 260);
        //String ury = String.valueOf(Integer.parseInt(lly) - 36);

        Properties params = new Properties();
        params.setProperty(PDFSigner.SIGNING_LOCATION, "");
        params.setProperty(PDFSigner.SIGNING_REASON, "Firmado digitalmente con RUBRICA");
        params.setProperty(PDFSigner.SIGN_TIME, FECHA_HORA);
        params.setProperty(PDFSigner.LAST_PAGE, "1");
        params.setProperty(PDFSigner.TYPE_SIG, "QR");
        params.setProperty(PDFSigner.INFO_QR, "Firmado digitalmente con RUBRICA\nhttps://minka.gob.ec/rubrica/rubrica");
        //params.setProperty(PDFSigner.TYPE_SIG, "information2");
        //params.setProperty(PDFSigner.FONT_SIZE, "4.5");
        // Posicion firma
        params.setProperty(PdfUtil.positionOnPageLowerLeftX, llx);
        params.setProperty(PdfUtil.positionOnPageLowerLeftY, lly);
        //params.setProperty(PdfUtil.positionOnPageUpperRightX, urx);
        //params.setProperty(PdfUtil.positionOnPageUpperRightY, ury);

        ////// LEER PDF:
        byte[] pdf = Documento.loadFile(FILE_PDF);

        // ARCHIVO
        KeyStoreProvider ksp = new FileKeyStoreProvider(ARCHIVO);
        KeyStore keyStore = ksp.getKeystore(PASSWORD.toCharArray());
        // TOKEN
        //KeyStore keyStore = KeyStoreProviderFactory.getKeyStore(password);

        byte[] signedPdf = null;
        PDFSigner signer = new PDFSigner();
        String alias = seleccionarAlias(keyStore);
        PrivateKey key = (PrivateKey) keyStore.getKey(alias, PASSWORD.toCharArray());
        Certificate[] certChain = keyStore.getCertificateChain(alias);
        signedPdf = signer.sign(pdf, "SHA1withRSA", key, certChain, params);
        System.out.println("final firma\n-------");
        ////// Permite guardar el archivo en el equipo
        java.io.FileOutputStream fos = new java.io.FileOutputStream(io.rubrica.validaciones.Fichero.ruta());
        fos.write(signedPdf);
        fos.close();
    }

    private static void validarCertificado() throws IOException, KeyStoreException, Exception {
        // ARCHIVO
        KeyStoreProvider ksp = new FileKeyStoreProvider(ARCHIVO);
        KeyStore keyStore = ksp.getKeystore(PASSWORD.toCharArray());
        // TOKEN
        //KeyStore keyStore = KeyStoreProviderFactory.getKeyStore(password);

        String alias = seleccionarAlias(keyStore);
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(alias);
        System.out.println("UID: " + Utils.getUID(x509Certificate));
        System.out.println("CN: " + Utils.getCN(x509Certificate));
        System.out.println("emisión: " + CertEcUtils.getNombreCA(x509Certificate));
        System.out.println("fecha emisión: " + x509Certificate.getNotBefore());
        System.out.println("fecha expiración: " + x509Certificate.getNotAfter());

        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
        TemporalAccessor accessor = dateTimeFormatter.parse(FECHA_HORA);
        Date fechaHoraISO = Date.from(Instant.from(accessor));

        //Validad certificado revocado
        Date fechaRevocado = UtilsCrlOcsp.validarFechaRevocado(x509Certificate);
        if (fechaRevocado != null && fechaRevocado.compareTo(fechaHoraISO) <= 0) {
            System.out.println("Certificado revocado: "+fechaRevocado);
        }
        if (fechaHoraISO.compareTo(x509Certificate.getNotBefore()) <= 0 || fechaHoraISO.compareTo(x509Certificate.getNotAfter()) >= 0) {
            System.out.println("Certificado caducado");
        }
        System.out.println("Certificado emitido por entidad certificadora acreditada? " + Utils.verifySignature(x509Certificate));
    }

    private static void verificarPDF() throws IOException, InvalidFormatException, SignatureException, Exception {
        ////// LEER PDF:
        byte[] pdf = Documento.loadFile(FILE_PDF);
        List<Certificado> certificados = Utils.pdfToCertificados(pdf);
        certificados.forEach((certificado) -> {
            System.out.println(certificado.toString());
        });
    }

    private static void verificarP7M() throws IOException, SignatureVerificationException, Exception {
        String fileP7m = "/home/mfernandez/Decretos firmados/1.pdf.p7m";
        byte[] p7m = Documento.loadFile(fileP7m);

        VerificadorCMS verificadorCMS = new VerificadorCMS();
        byte[] signedP7m = verificadorCMS.verify(p7m);

        java.io.FileOutputStream fosP7m = new java.io.FileOutputStream(io.rubrica.validaciones.Fichero.ruta());
        fosP7m.write(signedP7m);
        fosP7m.close();
    }
}
