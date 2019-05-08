/*
 * Firma Digital: Cliente
 * Copyright 2017 Secretaría Nacional de la Administración Pública
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.rubrica.utils;

import io.rubrica.exceptions.CertificadoInvalidoException;
import io.rubrica.exceptions.HoraServidorException;
import io.rubrica.certificate.CertEcUtils;
import io.rubrica.exceptions.EntidadCertificadoraNoValidaException;
import io.rubrica.exceptions.RubricaException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import io.rubrica.sign.cms.DatosUsuario;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Date;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.swing.JOptionPane;

/**
 * Validacion de cedula.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class X509CertificateUtils {

    private final ResourceBundle MESSAGES = ResourceBundle.getBundle("Messages", Locale.getDefault());

    private String revocado = null;
    private boolean caducado = false;
    private boolean desconocido = false;

    public X509CertificateUtils() {
    }

    public boolean isCaducado() {
        return caducado;
    }

    public boolean isDesconocido() {
        return desconocido;
    }

    public String getRevocado() {
        return revocado;
    }

    public static String getCedula(KeyStore keyStore, String alias) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            DatosUsuario datosUsuario = CertEcUtils.getDatosUsuarios(certificate);
            return datosUsuario.getCedula();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean validarX509Certificate(X509Certificate x509Certificate) throws RubricaException, KeyStoreException, EntidadCertificadoraNoValidaException, InvalidKeyException, CertificadoInvalidoException, IOException, HoraServidorException {
        boolean retorno = false;
        if (x509Certificate != null) {
            Date fechaHora = TiempoUtils.getFechaHora();

            Date fechaRevocado = UtilsCrlOcsp.validarFechaRevocado(x509Certificate);
            if (fechaRevocado != null && fechaRevocado.compareTo(fechaHora) <= 0) {
                revocado = fechaRevocado.toString();
            }
            if (fechaHora.compareTo(x509Certificate.getNotBefore()) <= 0 || fechaHora.compareTo(x509Certificate.getNotAfter()) >= 0) {
                caducado = true;
            }

            if (!io.rubrica.utils.Utils.verifySignature(x509Certificate)) {
                desconocido = true;
            }

            if ((revocado!=null) || caducado || desconocido) {
                JOptionPane.showMessageDialog(null, MESSAGES.getString("mensaje.error.certificado_invalido"), "Advertencia", JOptionPane.WARNING_MESSAGE);
            } else {
                retorno = true;
            }
        }
        return retorno;
    }
}