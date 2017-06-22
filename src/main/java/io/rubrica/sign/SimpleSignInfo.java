/*
 * Copyright 2009-2017 Rubrica
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

package io.rubrica.sign;

import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;

import io.rubrica.core.Util;

/**
 * Clase dise&ntilde;ada para almacenar la informaci&oacute;n m&iacute;nima
 * extraida de un objeto simple de firma.
 */
public class SimpleSignInfo {

	/** Cadena de certificaci&oacute;n. */
	private X509Certificate[] certs = null;

	/** Algoritmo de firma. */
	private String signAlgorithm = null;

	/** Formato de firma. */
	private String signFormat = null;

	/** Momento de la firma segundo el dispositivo que la realiz&oacute;. */
	private Date signingTime = null;

	/** Momento de la firma seg&uacute;n un sello uan TSA. */
	private Date[] timestampingTime = null;

	/** Cadena binaria con el PKCS#1 de la firma individual. */
	//private byte[] pkcs1 = null;

	/**
	 * Construye un objeto con la informaci&oacute;n b&aacute;sica:
	 * <ul>
	 * <li>La cadena de certificaci&oacute;n (obligatoria).</li>
	 * <li>La fecha de firma (opcional).</li>
	 * </ul>
	 * Si no se dispone de la cadena de certificaci&oacute;n completa se
	 * indicar&aacute; al menos el certificado usado para la firma.
	 * 
	 * @param chainCert
	 *            Cadena de certificaci&oacute;n.
	 * @param signingTime
	 *            Momento de la firma.
	 */
	public SimpleSignInfo(final X509Certificate[] chainCert, final Date signingTime) {

		if (chainCert == null || chainCert.length == 0 || chainCert[0] == null) {
			throw new IllegalArgumentException("No se ha introducido la cadena de certificacion"); //$NON-NLS-1$
		}

		this.certs = chainCert.clone();
		this.signingTime = signingTime;
	}

	/**
	 * Obtiene el algoritmo de firma.
	 * 
	 * @return Algoritmo de firma
	 */
	public String getSignAlgorithm() {
		return this.signAlgorithm;
	}

	/**
	 * Establece el algoritmo de firma
	 * 
	 * @param algorithm
	 *            Algoritmo de firma
	 */
	public void setSignAlgorithm(final String algorithm) {
		this.signAlgorithm = algorithm;
	}

	/**
	 * Obtiene el formato de firma.
	 * 
	 * @return Formato de firma
	 */
	public String getSignFormat() {
		return this.signFormat;
	}

	/**
	 * Establece el formato de firma.
	 * 
	 * @param format
	 *            Formato de firma
	 */
	public void setSignFormat(final String format) {
		this.signFormat = format;
	}

	/**
	 * Obtiene las fechas de los sellos de tiempo de la firma.
	 * 
	 * @return Fechas de los sellos de tiempo
	 */
	public Date[] getTimestampingTime() {
		return this.timestampingTime == null ? null : this.timestampingTime.clone();
	}

	/**
	 * Establece las fechas de los sellos de tiempo de la firma.
	 * 
	 * @param timestampingTime
	 *            Fechas de los sellos de tiempo
	 */
	public void setTimestampingTime(final Date[] timestampingTime) {
		this.timestampingTime = timestampingTime == null ? null : timestampingTime.clone();
	}

	/**
	 * Obtiene el certificado (con su cadena de confianza) de la firma.
	 * 
	 * @return Certificado (con su cadena de confianza) de la firma
	 */
	public X509Certificate[] getCerts() {
		return this.certs == null ? null : this.certs.clone();
	}

	/**
	 * Obtiene la fecha de la firma.
	 * 
	 * @return Fecha de la firma
	 */
	public Date getSigningTime() {
		return this.signingTime;
	}

	/**
	 * Indica si la firma dispone de un sello de tiempo.
	 * 
	 * @return Devuelve <code>true</code> si la firma tiene un sello de tiempo,
	 *         <code>false</code> en caso contrario.
	 */
	public boolean isTimeStamped() {
		return this.timestampingTime != null && this.timestampingTime.length > 0 && this.timestampingTime[0] != null;
	}

	/**
	 * Recupera el PKCS#1 de la firma en cuesti&oacute;n. Devuelve {@code null}
	 * si no se preestablecio.
	 * 
	 * @return PKCS#1 de la firma.
	 */
	//public byte[] getPkcs1() {
		//return this.pkcs1 == null ? null : this.pkcs1.clone();
	//}

	/**
	 * Establece el PKCS#1 de la firma.
	 * 
	 * @param pkcs1
	 *            PKCS#1 que gener&oacute; la firma.
	 */
	//public void setPkcs1(final byte[] pkcs1) {
		//this.pkcs1 = pkcs1 == null ? null : pkcs1.clone();
	//}

	@Override
	public String toString() {
		String desc = Util.getCN(this.certs[0]);
		if (this.timestampingTime != null && this.timestampingTime.length > 0 && this.timestampingTime[0] != null) {
			desc += " (TimeStamp: "
					+ DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT).format(this.signingTime)
					+ ")";
		} else if (this.signingTime != null) {
			desc += " (" + DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT).format(this.signingTime)
					+ ")";
		}

		return desc;
	}
}