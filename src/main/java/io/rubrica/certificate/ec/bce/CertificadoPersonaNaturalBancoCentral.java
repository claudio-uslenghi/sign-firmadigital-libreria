/*
 * Copyright 2009-2018 Rubrica
 *
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
package io.rubrica.certificate.ec.bce;

import java.security.cert.X509Certificate;

import io.rubrica.certificate.ec.CertificadoPersonaNatural;

/**
 * Certificado de persona natural emitido por el Banco Central del Ecuador.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class CertificadoPersonaNaturalBancoCentral extends CertificadoBancoCentral
        implements CertificadoPersonaNatural {

    public CertificadoPersonaNaturalBancoCentral(X509Certificate certificado) {
        super(certificado);
    }
}
