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

package io.rubrica.keystore;

import java.io.File;

/**
 * Implementacion de <code>KeyStoreProvider</code> para utilizar con librerias
 * PKCS#11 de iKey Pro, instaladas previamente.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class IKeyProKeyStoreProvider extends PKCS11KeyStoreProvider {

	private static final String CONFIG;
	private static final String DRIVER_FILE_32_BITS = "/usr/lib/libiKeyTokenEngine.so";
	private static final String DRIVER_FILE_64_BITS = "/usr/lib64/libiKeyTokenEngine.so";

	static {
		StringBuffer config = new StringBuffer();
		config.append("name=Safenetikey2032\n");
		config.append("library=").append(is64bit() ? DRIVER_FILE_64_BITS : DRIVER_FILE_32_BITS).append("\n");
		config.append("disabledMechanisms={ CKM_SHA1_RSA_PKCS }");
		CONFIG = config.toString();
	}

	@Override
	public String getConfig() {
		return CONFIG;
	}

	@Override
	public boolean existeDriver() {
		File driver = is64bit() ? new File(DRIVER_FILE_64_BITS) : new File(DRIVER_FILE_32_BITS);
		return driver.exists();
	}
}