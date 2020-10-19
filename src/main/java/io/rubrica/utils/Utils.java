/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.rubrica.utils;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import io.rubrica.certificate.CertEcUtils;
import io.rubrica.certificate.to.Certificado;
import io.rubrica.core.Util;
import io.rubrica.exceptions.*;
import io.rubrica.sign.Main;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.certificate.to.DatosUsuario;
import io.rubrica.certificate.to.Documento;
import io.rubrica.sign.cms.VerificadorCMS;
import io.rubrica.sign.odf.ODFSigner;
import io.rubrica.sign.pdf.PDFSigner;
import io.rubrica.sign.xades.XAdESSigner;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.rmi.server.ExportException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.management.openmbean.InvalidKeyException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import org.w3c.dom.Node;

/**
 * M&eacute;todos generales de utilidad para toda la aplicaci&oacute;n.
 */
public class Utils {

    private static final int BUFFER_SIZE = 4096;

    private static final Logger logger = Logger.getLogger(Utils.class.getName());
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Obtiene el flujo de entrada de un fichero (para su lectura) a partir de
     * su URI.
     *
     * @param uri URI del fichero a leer
     * @return Flujo de entrada hacia el contenido del fichero
     * @throws IOException Cuando no se ha podido abrir el fichero de datos.
     */
    public static InputStream loadFile(URI uri) throws IOException {

        if (uri == null) {
            throw new IllegalArgumentException("Se ha pedido el contenido de una URI nula");
        }

        if (uri.getScheme().equals("file")) {
            // Es un fichero en disco. Las URL de Java no soportan file://, con
            // lo que hay que diferenciarlo a mano

            // Retiramos el "file://" de la uri
            String path = uri.getSchemeSpecificPart();
            if (path.startsWith("//")) {
                path = path.substring(2);
            }
            return new FileInputStream(new File(path));
        }

        // Es una URL
        InputStream tmpStream = new BufferedInputStream(uri.toURL().openStream());
        byte[] tmpBuffer = getDataFromInputStream(tmpStream);
        return new ByteArrayInputStream(tmpBuffer);
    }

    public static byte[] getBytesFromFile(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }

    /**
     * Lee un flujo de datos de entrada y los recupera en forma de array de
     * bytes. Este m&eacute;todo consume pero no cierra el flujo de datos de
     * entrada.
     *
     * @param input Flujo de donde se toman los datos.
     * @return Los datos obtenidos del flujo.
     * @throws IOException Cuando ocurre un problema durante la lectura
     */
    public static byte[] getDataFromInputStream(InputStream input) throws IOException {
        if (input == null) {
            return new byte[0];
        }
        int nBytes;
        byte[] buffer = new byte[BUFFER_SIZE];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((nBytes = input.read(buffer)) != -1) {
            baos.write(buffer, 0, nBytes);
        }
        return baos.toByteArray();
    }

    /**
     * Obtiene el UID del titular de un certificado X.509. Si no se encuentra el
     * CN, se devuelve la unidad organizativa (Organization Unit, OU).
     *
     * @param c Certificado X.509 del cual queremos obtener el nombre
     *          com&uacute;n
     * @return Nombre com&uacute;n (Common Name, UID) del titular de un
     * certificado X.509
     */
    public static String getUID(X509Certificate c) {
        if (c == null) {
            return null;
        }
        return getUID(c.getSubjectX500Principal().toString());
    }

    /**
     * Obtiene el UID de un <i>Principal</i>
     * X.400. Si no se encuentra el CN, se devuelve la unidad organizativa
     * (Organization Unit, OU).
     *
     * @param principal <i>Principal</i> del cual queremos obtener el nombre com&uacute;n
     * @return Nombre com&uacute;n (Common Name, UID) de un <i>Principal</i>
     * X.400
     */
    public static String getUID(final String principal) {
        if (principal == null) {
            return null;
        }

        String rdn = getRDNvalueFromLdapName("uid", principal);
        if (rdn != null) {
            return rdn;
        }

        final int i = principal.indexOf('=');
        if (i != -1) {
            logger.warning(
                    "No se ha podido obtener el UID, se devolvera el fragmento mas significativo");
            return getRDNvalueFromLdapName(principal.substring(0, i), principal);
        }

        logger.warning("Principal no valido, se devolvera la entrada");
        return principal;
    }

    /**
     * Obtiene el nombre com&uacute;n (Common Name, CN) del titular de un
     * certificado X.509. Si no se encuentra el CN, se devuelve la unidad
     * organizativa (Organization Unit, OU).
     *
     * @param c Certificado X.509 del cual queremos obtener el nombre
     *          com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) del titular de un
     * certificado X.509
     */
    public static String getCN(X509Certificate c) {
        if (c == null) {
            return null;
        }
        return getCN(c.getSubjectX500Principal().toString());
    }

    /**
     * Obtiene el nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     * X.400. Si no se encuentra el CN, se devuelve la unidad organizativa
     * (Organization Unit, OU).
     *
     * @param principal <i>Principal</i> del cual queremos obtener el nombre com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     * X.400
     */
    public static String getCN(final String principal) {
        if (principal == null) {
            return null;
        }

        String rdn = getRDNvalueFromLdapName("cn", principal);
        if (rdn == null) {
            rdn = getRDNvalueFromLdapName("ou", principal);
        }

        if (rdn != null) {
            return rdn;
        }

        final int i = principal.indexOf('=');
        if (i != -1) {
            logger.warning(
                    "No se ha podido obtener el Common Name ni la Organizational Unit, se devolvera el fragmento mas significativo");
            return getRDNvalueFromLdapName(principal.substring(0, i), principal);
        }

        logger.warning("Principal no valido, se devolvera la entrada");
        return principal;
    }

    /**
     * Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un
     * principal. El valor de retorno no incluye el nombre del RDN, el igual, ni
     * las posibles comillas que envuelvan el valor. La funci&oacute;n no es
     * sensible a la capitalizaci&oacute;n del RDN. Si no se encuentra, se
     * devuelve {@code null}.
     *
     * @param rdn       RDN que deseamos encontrar.
     * @param principal Principal del que extraer el RDN (seg&uacute;n la
     *                  <a href="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</a>).
     * @return Valor del RDN indicado o {@code null} si no se encuentra.
     */
    public static String getRDNvalueFromLdapName(final String rdn, final String principal) {
        int offset1 = 0;

        while ((offset1 = principal.toLowerCase(Locale.US).indexOf(rdn.toLowerCase(), offset1)) != -1) {
            if (offset1 > 0 && principal.charAt(offset1 - 1) != ',' && principal.charAt(offset1 - 1) != ' ') {
                offset1++;
                continue;
            }

            offset1 += rdn.length();
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return null;
            }

            if (principal.charAt(offset1) != '=') {
                continue;
            }

            offset1++;
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return "";
            }

            int offset2;
            if (principal.charAt(offset1) == ',') {
                return "";
            } else if (principal.charAt(offset1) == '"') {
                offset1++;
                if (offset1 >= principal.length()) {
                    return "";
                }

                offset2 = principal.indexOf('"', offset1);
                if (offset2 == offset1) {
                    return "";
                } else if (offset2 != -1) {
                    return principal.substring(offset1, offset2);
                } else {
                    return principal.substring(offset1);
                }
            } else {
                offset2 = principal.indexOf(',', offset1);
                if (offset2 != -1) {
                    return principal.substring(offset1, offset2).trim();
                }
                return principal.substring(offset1).trim();
            }
        }

        return null;
    }

    public static X509Certificate getCertificate(Node certificateNode) {
        return createCert(certificateNode.getTextContent().trim().replace("\r", "").replace("\n", "").replace(" ", "")
                .replace("\t", ""));
    }

    public static X509Certificate createCert(String b64Cert) {
        if (b64Cert == null || b64Cert.isEmpty()) {
            logger.severe("Se ha proporcionado una cadena nula o vacia, se devolvera null");
            return null;
        }
        X509Certificate cert;
        try (InputStream isCert = new ByteArrayInputStream(Base64.getDecoder().decode(b64Cert));) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(isCert);
            try {
                isCert.close();
            } catch (Exception e) {
                logger.warning("Error cerrando el flujo de lectura del certificado: " + e);
            }
        } catch (Exception e) {
            logger.severe("No se pudo decodificar el certificado en Base64, se devolvera null: " + e);
            return null;
        }
        return cert;
    }

    public static Date getSignTime(String fechaHora) {
        DateTimeFormatter timeFormatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

        try {
            TemporalAccessor accessor = timeFormatter.parse(fechaHora);
            return Date.from(Instant.from(accessor));
        } catch (DateTimeParseException e) {
            logger.severe("La fecha indicada ('" + fechaHora
                    + "') como momento de firma para PDF no sigue el patron ISO-8601: " + e);
            return new Date();
        }
    }

    public static List<Certificado> datosP7mToCertificado(List<X509Certificate> certificados, List<Date> fechasFirmados) throws RubricaException, HoraServidorException, IOException, CertificadoInvalidoException, EntidadCertificadoraNoValidaException, ConexionValidarCRLException, CRLValidationException, OcspValidationException {
        List<Certificado> tempCertificados = new ArrayList<>();
        for (int i = 0; i < certificados.size(); i++) {
            X509Certificate temp = certificados.get(i);
            Date fechaFirmado = fechasFirmados.get(i);
            DatosUsuario datosUsuario = CertEcUtils.getDatosUsuarios(temp);
            Certificado certificado = new Certificado(
                    Util.getCN(temp),
                    CertEcUtils.getNombreCA(temp),
                    dateToCalendar(temp.getNotBefore()),
                    dateToCalendar(temp.getNotAfter()),
                    dateToCalendar(fechaFirmado),
                    dateToCalendar(UtilsCrlOcsp.validarFechaRevocado(temp)),
                    esValido(temp, fechaFirmado),
                    datosUsuario);

            tempCertificados.add(certificado);
        }
        return tempCertificados;
    }

    public static Documento pdfToDocumento(byte[] pdf) throws IOException, SignatureVerificationException, Exception {
        List<Certificado> certificados = new ArrayList<>();
        Documento documento = new Documento(true, false, certificados, null);

        Signer signer = new PDFSigner();
        java.util.List<SignInfo> signInfos;
        signInfos = signer.getSigners(pdf);
        if (signInfos == null || signInfos.isEmpty()) {
            return new Documento(false, false, certificados, "Documento sin firmas");
//            throw new DocumentoException("Documento sin firmas");
        } else {
            for (SignInfo signInfo : signInfos) {
                Certificado certificado = signInfoToCertificado(signInfo);
                try {
                    PdfReader pdfReader = new PdfReader(pdf);
                    java.util.List<String> signatureNames = pdfReader.getAcroFields().getSignatureNames();
                    for (String signatureName : signatureNames) {
                        // Retorma la firma en formato PKCS7
                        PdfPKCS7 pdfPKCS7 = pdfReader.getAcroFields().verifySignature(signatureName);
                        // Validacion Sellado de Tiempo
                        TimeStampToken tsToken = pdfPKCS7.getTimeStampToken();
                        Date fechaDocFirmado;
                        if (tsToken != null) { // Timestamping Change Openpdf to itext
                            TimeStampTokenInfo tsInfo = tsToken.getTimeStampInfo();
                            certificado.setDocTimeStamp(true);
                            fechaDocFirmado = tsInfo.getGenTime();
                        } else {
                            fechaDocFirmado = pdfPKCS7.getSignDate().getTime();
                        }
                        if (signInfo.getSigningTime().equals(fechaDocFirmado)) {
                            for (X509Certificate certificate : signInfo.getCerts()) {
                                if (pdfPKCS7.getSigningCertificate().equals(certificate)) {
                                    certificado.setDocReason(pdfPKCS7.getReason());
                                    certificado.setDocLocation(pdfPKCS7.getLocation());
                                    certificado.setSignVerify(pdfPKCS7.verify());
                                    //documento sin ser modificado
                                    if (!documento.getDocValidate()) {
                                        documento.setDocValidate(pdfReader.getAcroFields().signatureCoversWholeDocument(signatureName));
                                    }
                                    certificado.setDocTimeStamp(false);
                                    // Obtiene KeyUsages
                                    certificado.setKeyUsages(validacionKeyUsages(pdfPKCS7.getSigningCertificate()));
//                                    System.out.println("--------------signatureName--------------");
//                                    System.out.println("Signature covers whole document: " + pdfReader.getAcroFields().signatureCoversWholeDocument(signatureName)); //si esta modificado
//                                    System.out.println("docModify(pdfReader, pdfPKCS7): "+docModify(pdfReader, pdfPKCS7));
//                                    InputStream revisionStream = pdfReader.getAcroFields().extractRevision(signatureName);
//                                    PdfReader pdfReaderRevision = new PdfReader(revisionStream);
//                                    for (String signatureNameRevision : pdfReaderRevision.getAcroFields().getSignatureNames()) {
//                                        String nameRevision = signatureNameRevision;
//                                        System.out.println("++++++++++++++signatureNameRevision++++++++++++++");
//                                        System.out.println("Signature covers whole document: " + pdfReaderRevision.getAcroFields().signatureCoversWholeDocument(nameRevision)); //si esta modificado
//                                        System.out.println("Document revision: " + pdfReaderRevision.getAcroFields().getRevision(nameRevision) + "/" + pdfReaderRevision.getAcroFields().getTotalRevisions());
//                                        System.out.println("docModify(pdfReaderRevision, pdfReader.getAcroFields().verifySignature(signatureNameRevision)): "+docModify(pdfReaderRevision, pdfReader.getAcroFields().verifySignature(signatureNameRevision)));
//                                        System.out.println("++++++++++++++++++++++++++++");
//                                    }
//                                    System.out.println("----------------------------");
                                    break;
                                }
                            }
                        }
                    }
                } catch (IOException | SignatureException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
                certificados.add(certificado);
            }

            if (certificados != null || !certificados.isEmpty()) {
                for (Certificado certificado : certificados) {
                    System.out.println(certificado.getRevocated());
                    System.out.println(certificado.getSignVerify());
                    System.out.println(certificado.getValidated());
                    System.out.println(certificado.getDatosUsuario().isCertificadoDigitalValido());
                    //certificado digital sin ser revocado, integridad de la firma, dentro de fecha de figencia, válido por CA
                    if (certificado.getRevocated() != null || !certificado.getSignVerify() || !certificado.getValidated() || !certificado.getDatosUsuario().isCertificadoDigitalValido()) {
                        documento.setSignValidate(false);
                        break;
                    }
                }
            }
            documento.setCertificados(certificados);
        }
        return documento;
    }

    /**
     * Valida que los keyusage sean por lo menos digitalSignature y
     * NonRepudiation
     *
     * @param signCert
     * @return
     */
    private static String validacionKeyUsages(X509Certificate signCert) throws CertificateParsingException {
        String keyUsages = "";
        boolean[] keyUsage = signCert.getKeyUsage();
        if (keyUsage[0]) {
            keyUsages += "Firma Electrónica, ";// digitalSignature
        }

        if (keyUsage[1]) {
            keyUsages += "No Repudio, "; // nonRepudiation
        }

        if (keyUsage[2]) {
            keyUsages += "Cifrado de llave, ";// keyEncipherment
        }

        if (keyUsage[3]) {
            keyUsages += "Cifrado de datos, ";// dataEncipherment
        }

        if (keyUsage[4]) {
            keyUsages += "Acuerdo de llaves, "; // keyAgreement
        }

        if (keyUsage[5]) {
            keyUsages += "Firma y certificado de llave, ";// keyCertSign
        }

        if (keyUsage[6]) {
            keyUsages += "Firma de CRL, ";// cRLSign
        }

        if (keyUsage[7]) {
            keyUsages += "Solo cifrado, ";// encipherOnly
        }

        if (keyUsage[8]) {
            keyUsages += "Solo descifrado"; // decipherOnly
        }
        return keyUsages;
    }

    public static Documento signInfosToCertificados(List<SignInfo> signInfos) throws DocumentoException, CertificadoInvalidoException, IOException {
        Documento documento = null;
        List<Certificado> certificados = new ArrayList<>();
        if (signInfos == null || signInfos.isEmpty()) {
            return new Documento(false, false, certificados, "Documento sin firmas");
        } else {
            for (SignInfo signInfo : signInfos) {
                certificados.add(signInfoToCertificado(signInfo));
            }
        }
        documento.setCertificados(certificados);
        return documento;
    }

    public static Certificado signInfoToCertificado(SignInfo signInfo) throws CertificadoInvalidoException, IOException {
        signInfo.getCerts();
        Certificado certificado = null;
        DatosUsuario datosUsuario = CertEcUtils.getDatosUsuarios(signInfo.getCerts()[0]);
        if (datosUsuario == null) {
            //extraer información del certificado
            X500Principal issuerX500Principal = signInfo.getCerts()[0].getIssuerX500Principal();//CA
            X500Name issuerX500name = new X500Name(issuerX500Principal.getName());
            X500Principal subjectX500Principal = signInfo.getCerts()[0].getSubjectX500Principal();//firmante
            X500Name subjectX500name = new X500Name(subjectX500Principal.getName());
            String cedula = "", nombre = "", entidadCertificadora = "";
            try {
                nombre = subjectX500name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();//CommonName
                cedula = subjectX500name.getRDNs(BCStyle.SERIALNUMBER)[0].getFirst().getValue().toString();//SerialNumber
                entidadCertificadora = issuerX500name.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();//OrganizationName
            } catch (java.lang.ArrayIndexOutOfBoundsException aioobe) {
            }
            //creando objeto para leer info
            datosUsuario = new DatosUsuario();
            datosUsuario.setCedula(cedula);
            datosUsuario.setNombre(nombre);
            datosUsuario.setEntidadCertificadora(entidadCertificadora);
            datosUsuario.setCertificadoDigitalValido(false);
        }
        certificado = new Certificado(
                Util.getCN(signInfo.getCerts()[0]),
                CertEcUtils.getNombreCA(signInfo.getCerts()[0]),
                dateToCalendar(signInfo.getCerts()[0].getNotBefore()),
                dateToCalendar(signInfo.getCerts()[0].getNotAfter()),
                dateToCalendar(signInfo.getSigningTime()),
                dateToCalendar(UtilsCrlOcsp.validarFechaRevocado(signInfo.getCerts()[0])),
                esValido(signInfo.getCerts()[0], signInfo.getSigningTime()),
                datosUsuario);
        return certificado;
    }

    public static Calendar dateToCalendar(Date date) {
        Calendar calendar = null;
        if (date != null) {
            calendar = Calendar.getInstance();
            calendar.setTime(date);
        }
        return calendar;
    }

    /**
     * Si el certificado ya caduco
     *
     * @param cert
     * @param signingTime
     * @return
     */
    public static boolean esValido(X509Certificate cert, Date signingTime) {
        return !(signingTime.before(cert.getNotBefore()) || signingTime.after(cert.getNotAfter()));
    }

    public static Signer documentSigner(File documento) {
        String extDocumento = FileUtils.getFileExtension(documento);
        switch (extDocumento.toLowerCase()) {
            case "pdf":
                return new PDFSigner();
//            case "docx":
//            case "xlsx":
//            case "pptx":
//                return new OOXMLSigner();
            case "odt":
            case "ods":
            case "odp":
                return new ODFSigner();
            case "xml":
                return new XAdESSigner();
            default:
                return null;
        }
    }

    public static Documento verificarDocumento(File file) throws IOException, KeyStoreException, OcspValidationException, SignatureException, RubricaException, ConexionInvalidaOCSPException, HoraServidorException, CertificadoInvalidoException, EntidadCertificadoraNoValidaException, ConexionValidarCRLException, SignatureVerificationException, DocumentoException, CRLValidationException, Exception {
        byte[] docByteArray = FileUtils.fileConvertToByteArray(file);
        // para P7m, ya que p7m no tiene signer
        Documento documento = null;

        String extDocumento = FileUtils.getExtension(docByteArray);
        if (extDocumento.toLowerCase().contains(".p7s")) {
            VerificadorCMS verificador = new VerificadorCMS();
            byte[] archivoOriginal = verificador.verify(docByteArray);

            String nombreArchivo = FileUtils.crearNombreVerificado(file, FileUtils.getExtension(archivoOriginal));
            System.out.println("nombreDocFirmado: " + nombreArchivo);

            FileUtils.saveByteArrayToDisc(archivoOriginal, nombreArchivo);
            FileUtils.abrirDocumento(nombreArchivo);
            documento.setCertificados(Utils.datosP7mToCertificado(verificador.certificados, verificador.fechasFirmados));
            return documento;
        } else {
            if (extDocumento.toLowerCase().equals(".pdf")) {
                return Utils.pdfToDocumento(docByteArray);
            } else {
                //Documento documento = null;
                try {
                    Signer docSigner = Utils.documentSigner(file);
                    documento = Utils.signInfosToCertificados(docSigner.getSigners(docByteArray));
                    //SRI
//                String xml = leerXmlSRI(documento);
//                List<Certificado> certificadosSRI = Utils.signInfosToCertificados(docSigner.getSigners(xml.getBytes(StandardCharsets.UTF_8)));
//                if (!certificadosSRI.isEmpty()) {
//                    javax.swing.JOptionPane.showMessageDialog(null, PropertiesUtils.getMessages().getProperty("mensaje.error.documento_sri"), "Advertencia", javax.swing.JOptionPane.WARNING_MESSAGE);
//                }
//                certificados.addAll(certificadosSRI);
                    //SRI
                } catch (NullPointerException npe) {
                    List<Certificado> certificados = new ArrayList<>();
                    return new Documento(false, false, certificados, "El archivo no es un PDF");
                } catch (InvalidFormatException ife) {
                    List<Certificado> certificados = new ArrayList<>();
                    return new Documento(false, false, certificados, "El archivo no es un PDF");
                }
                return documento;
            }
        }
    }

    public static String leerXmlSRI(File documento) {
        Scanner entrada = null;
        //String xml
        String xml = "";
        try {
            //creamos un Scanner para leer el fichero
            entrada = new Scanner(documento);
            while (entrada.hasNext()) { //mientras no se llegue al final del fichero
                xml += entrada.nextLine();  //se lee una línea
            }
            xml = xml.replaceAll("&lt;", "<");
            xml = xml.replaceAll("&gt;", ">");
            //Texto a buscar
            String inicioTexto1 = "<comprobante><![CDATA[";
            String finTexto1 = "]]></comprobante>";
            String inicioTexto2 = "<comprobante>";
            String finTexto2 = "</comprobante>";
            if (xml.contains(inicioTexto1)) {   //si la línea contiene el texto buscado
                xml = xml.substring(xml.lastIndexOf(inicioTexto1) + inicioTexto1.length(),
                        xml.indexOf(finTexto1));
            } else {   //si la línea contiene el texto buscado
                xml = xml.substring(xml.lastIndexOf(inicioTexto2) + inicioTexto2.length(),
                        xml.indexOf(finTexto2));
            }
        } catch (Exception e) {
            System.out.println(e.toString());
        } finally {
            if (entrada != null) {
                entrada.close();
            }
        }
        return xml;
    }

    public static String validarFirma(Calendar fechaDesde, Calendar fechaHasta, Calendar fechaFirmado, Calendar fechaRevocado) {
        String retorno = "Válida";
        if (fechaFirmado.compareTo(fechaDesde) >= 0 && fechaFirmado.compareTo(fechaHasta) <= 0) {
            if (fechaRevocado != null && fechaRevocado.compareTo(fechaFirmado) <= 0) {
                retorno = "Inválida";
            }
        } else {
            retorno = "Inválida";
        }
        return retorno;
    }

    /**
     * Verifies that the given certificate was signed using the private key that
     * corresponds to the public key of the provided certificate.
     *
     * @param certificate The X509Certificate which is to be checked
     * @return True, if the verification was successful, false otherwise
     * @throws java.security.InvalidKeyException
     * @throws io.rubrica.exceptions.EntidadCertificadoraNoValidaException
     */
    public static boolean verifySignature(X509Certificate certificate) throws java.security.InvalidKeyException, EntidadCertificadoraNoValidaException {
        return verifySignature(certificate, CertEcUtils.getRootCertificate(certificate));
    }

    public static boolean verifySignature(X509Certificate certificate, X509Certificate rootCertificate) throws java.security.InvalidKeyException, EntidadCertificadoraNoValidaException {
        if (rootCertificate != null) {
            PublicKey publicKeyForSignature = rootCertificate.getPublicKey();

            try {
                certificate.verify(publicKeyForSignature);
                return true;
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                    | NoSuchProviderException | SignatureException e) {
                System.out.println("\n"
                        + "\tSignature verification of certificate having distinguished name \n"
                        + "\t'" + certificate.getSubjectX500Principal() + "'\n"
                        + "\twith certificate having distinguished name (the issuer) \n"
                        + "\t'" + rootCertificate.getSubjectX500Principal() + "'\n"
                        + "\tfailed. Expected issuer has distinguished name \n"
                        + "\t'" + certificate.getIssuerX500Principal() + "' (" + e.getClass().getSimpleName() + ")");
            }
        }
        return false;
    }
}
