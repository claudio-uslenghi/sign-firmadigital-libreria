/* 
 * Copyright (C) 2017 FirmaEC
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

import java.awt.Desktop;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 *
 * @author jdc
 */
public class FileUtils {

    public static String getFileExtension(File file) {
        String name = file.getName();
        try {
            return name.substring(name.lastIndexOf(".") + 1).toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    public static String getFileExtension(String fileName) {
        try {
            return fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    public static String removeP7MExtension(File file) {
        String name = file.getName();
        int lastPeriodPos = name.lastIndexOf('.');
        return null;
    }

    public static byte[] fileConvertToByteArray(File file) throws IOException {
        Path documentoPath = Paths.get(file.getAbsolutePath());
        return Files.readAllBytes(documentoPath);
    }

    public static void saveByteArrayToDisc(byte[] archivo, String rutaNombre) throws FileNotFoundException, IOException {
        // TODO validar si hay otro archivo de momento lo sobre escribe
        FileOutputStream fos = new FileOutputStream(rutaNombre);
        File arc = new File(rutaNombre);

        Long espacio = arc.getFreeSpace();

        if (archivo != null) {
            System.out.println("bytes: " + archivo.length + " espacio " + espacio);

            if (espacio < archivo.length) {
                throw new IOException("No se puede crear el archivo firmado. No hay espacio suficiente en el disco");
            }
            fos.write(archivo);
            fos.close();
        } else {
            throw new IOException("No se puede firmar un documento de 0 bytes");
        }
    }

    // TODO Crear clase para manejar esto
    public static String crearNombreFirmado(File documento) {
        // buscamos el nombre para crear el signed
        // TODO validar si hay otro archivo de momento lo sobre escribe
        // USAR solo getAbsolutPath, talvez sin ruta
        String nombreCompleto = documento.getAbsolutePath();
        String nombre = nombreCompleto.replaceFirst("[.][^.]+$", "");
        //String extension = getFileExtension(documento);
        String extension = FileUtils.getFileExtension(documento);
        return nombre + "-signed." + extension;
    }

    public static String crearNombreArchivoP7M(File documento) throws IOException {
        // buscamos el nombre para crear el signed
        // TODO validar si hay otro archivo de momento lo sobre escribe
        // USAR solo getAbsolutPath, talvez sin ruta
        String nombreCompleto = documento.getAbsolutePath();
        String nombreSinP7m = nombreCompleto.replaceFirst("[.][^.]+$", "");
        String extension = getFileExtension(nombreSinP7m);
        String hora = TiempoUtils.getFechaHoraServidor();
        hora = hora.replace(":", "").replace(" ", "").replace(".", "").replace("-", "");
        hora = hora.substring(0, 20);
        extension = extension.length() > 5 ? "pdf" : extension;
        return nombreSinP7m + "-verified-" + hora + "." + extension;
    }

    public static void abrirDocumento(String documento) throws IOException {
        String OS = System.getProperty("os.name").toLowerCase();
        if (OS.contains("win")) {
            String cmd = "rundll32 url.dll,FileProtocolHandler " + documento;
            Runtime.getRuntime().exec(cmd);
        } else {
            File doc = new File(documento);
            Desktop.getDesktop().open(doc);
        }
    }

    public static String rutaFichero(javax.swing.filechooser.FileNameExtensionFilter filtro) {
        String ruta = "";
        javax.swing.JFileChooser jFileChooser = new javax.swing.JFileChooser(new java.io.File(System.getProperty("user.home")));
        jFileChooser.setAcceptAllFileFilterUsed(false);
        jFileChooser.setEnabled(false);
        jFileChooser.setFileFilter(filtro);

        int resultado = jFileChooser.showOpenDialog(null);
        if (resultado == javax.swing.JFileChooser.APPROVE_OPTION) {
            java.io.File file = new java.io.File(jFileChooser.getSelectedFile().toString());
            if (file.exists() && file.isFile()) {
                for (String filtre : filtro.getExtensions()) {
                    if (getFileExtension(file).equals(filtre)) {
                        ruta = file.toString();
                    }
                }
            }
        }
        return ruta;
    }
}
