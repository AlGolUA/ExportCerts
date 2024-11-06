package ua.com.csltd.algol;

import javax.net.ssl.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

class ExportUrlCerts {
    SSLContext sc;

    {
        // Create all-trusting host name verifier
        HostnameVerifier validHosts = (arg0, arg1) -> true;
        try {
            /* Start of Fix */
            TrustManager[] trustManagers = new TrustManager[] { new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }

            } };

            sc = SSLContext.getInstance("TLS");
            sc.init(null, trustManagers, null);

            sc = SSLContext.getInstance("SSL");
            sc.init(null, trustManagers, new SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
//            // All hosts will be valid
            HttpsURLConnection.setDefaultHostnameVerifier(validHosts);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void test(String url) throws IOException, CertificateEncodingException {
        SimpleDateFormat sd = new SimpleDateFormat("yyyy:MM:dd HH:mm:ss");
        // Установка соединения и получение сертификатов
        URL destinationURL = new URL(url);
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.setSSLSocketFactory(this.sc.getSocketFactory());
        conn.connect();

        // Извлечение сертификатов
        Certificate[] certs = conn.getServerCertificates();

        String baseFileName = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            String fileName = baseFileName + i + ".crt";
            try (FileOutputStream fos = new FileOutputStream(fileName)) {
                fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                fos.write(java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encode(cert.getEncoded()));
                fos.write("\n-----END CERTIFICATE-----\n".getBytes());
            }
            System.out.printf("Subject: %s  ---->  Issuer: %s%n", cert.getSubjectDN().toString(), cert.getIssuerDN().toString());
            System.out.printf("Valid from %s till %s%n", sd.format(cert.getNotBefore()), sd.format(cert.getNotAfter()));
            System.out.printf("Сертификат сохранен: %s%n", fileName);
        }
    }

    public static void main(String[] args) throws Exception {
//        String[] args = {"https://stackoverflow.com:443"};
        if (args.length == 0) {
            System.out.println("Usage: exportUrlCerts url");
            return;
        }
        new ExportUrlCerts().test(args[0]);
    }
}
