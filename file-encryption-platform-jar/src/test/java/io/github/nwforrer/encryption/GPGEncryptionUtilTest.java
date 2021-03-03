package io.github.nwforrer.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.SignatureException;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class GPGEncryptionUtilTest {
    private final GPGEncryptionUtil gpgEncryptionUtil = new GPGEncryptionUtil();

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void withCorrectKey_canDecryptStream() throws PGPException, SignatureException, IOException {
        String encryptedString = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "hIwD/otu4ZN3aMUBA/47TMJU6Y690ElXE+xBuVpjag2ptSG0S19Ao0BmYAwMe1bY\n" +
                "dia0Kuwrm3K5iAuvXJjM6JJ+OQY9ga7viY9+FCF1HYm43bBh2XDZNEqrBxhRU4Xd\n" +
                "74hdNLYSZNoWCROVEg3h+zCaDGXY+E4vXUGsHdpIenSsIsksCnn4Rf/ZbOPcbtJQ\n" +
                "AZcjqCN+uMKxa62Dt6bPbLvigUT0nf+jJhWhRsDiKt6XrR10Azk2pzNPyhZCZLc0\n" +
                "8Q6CroPZLTrJmcgNgZcLKmAch1dZaS2kKMnH9jzs16Q=\n" +
                "=Ms+1\n" +
                "-----END PGP MESSAGE-----\n";

        String privateKeyString = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lQIGBF8HbrwBBADEpcaCUtofj/HMGarbMSnioBl2fb+zh5CPYsuCcEFJMOpEk4kT\n" +
                "z8kLhOJctUuuwSdAzTqlcKPnnlSXl7EZR92Tr2RNl+jVMantWaOky1QCwt2tmF83\n" +
                "qC4H62/0NUo8z0ITjkByuFAW6mF5iva4izMxd3N/Dyl/p/lsjUBGwc7EHQARAQAB\n" +
                "/gcDAvrbkUDGjgfL6G16S8eGcUKmtLc0gMnjwthyJdBGmRMPc0TtjrGDgmL24CFV\n" +
                "jFcp65Kcogsxluoost6tRYOXtSkqWJbVkbzTxGTNE+odJO0/PMrD8mwgmsLWCl2+\n" +
                "eDZ58hexVW45KFrhxDFphRv4/uTZEQAc8S9x+ryRdBcFDYf71FRD4GjxMgG+cny3\n" +
                "sKKlcUCL1WtuptUbkZ5H6pUZ6pYVoEMb3a3bqDBUS8Ygm3t7F4Y/xM8WXNkB0HlN\n" +
                "/KwEOvuSSAI8sXhFwfb4RM+33npvKTEPVegijI3tH4PxxV42Je+TBWgIpOGDYNgi\n" +
                "gnBh4AvVhum+FGwiMn8bo2nEHcKwaGjapSIbzmsefa+dU6qX3RygrPm6g4y3BNtP\n" +
                "eXfb3KyrjVZJvK2J09oa8hT0lOzxpxaN47ShIvafc8qLUZjCRbrSUmC0ZgKRUvs3\n" +
                "iKrhU3NyW//Rdtfl4yPcINqYYnm2CzqalFQHD+DAIuKMIj2VPGCPvJq0GGFsZnJl\n" +
                "c2NvLWVuY3J5cHRpb24tdGVzdIjOBBMBCAA4FiEElKaRM98EX0DQaAUzhqgNkN6E\n" +
                "lr0FAl8HbrwCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQhqgNkN6Elr1u\n" +
                "VQP+MZbWfX2ci2Rvw+NjW3Ug3qr4Snh7qc9G7Ynty5LlelDlGFqvBOvqup8HmXH7\n" +
                "NzbkC8z/kqhuvdnZjD0xRgeh/PDWtymEVl48OYEqU+A9w369iiT+XFn9YOxxpEPx\n" +
                "plH4USKrfwYpY6JaZGuZ3mDmgifFri9jGqMVeMHfuXgEABmdAgYEXwduvAEEAMK2\n" +
                "h0Rpze+K/zqk/3cr6/3F6uQYn5M4bpa/GR3ZnkzD2nIoTZ4iC8szhQm7mXJzfALr\n" +
                "tlnNBNK5otyuHzB9KrREqQ0CVDZjxufcUcIjukrTcJ7gUBiaboXrA214wZYRQ85b\n" +
                "Ws6AvDQRECsw4vx0womlkWkk+c7UgSwl7A+L7fRnABEBAAH+BwMCb/3ERMpjk8To\n" +
                "vO3wMZskGc4eziCkgA2SQmx6m2mO5MPuMPkoYfMbOEXzek6bhzYluUtbOu74MFMk\n" +
                "1rRED0W+fe0wBuT2dXfpfWNBfY1CcLDh1uO8sCgd4bdApkqORj7BX/IxK0ljdMA3\n" +
                "ZF0tKAvw8A3FVj3zAEgRU5/iSZCd1AT1OdjPgtRIG7/khKayLUYIqH8K6WuaL+AH\n" +
                "0y5n9ZsXiRsmVF8N4huRNhNxCy3oadY+YxiOzxmBWFVZayM26gGpth6CzGPpAosb\n" +
                "hDlg4NWa7QSkO1Krn0cdQAYZWO8rmLRI5YucWcpJZ4IJ7NBfNvy0IGjPBEnDhHX9\n" +
                "mHBWio/eokFL2AWzR/fX39E4q/QgzQZOYVXaFS50WDmHOENHV+/XOtBuriAuhZ6s\n" +
                "FQu96o25bCDGV9MP3CT4l6ql3Keo5iUOLzD7F/2/CPAhTl8ZFGuJY5JvLhkk3B70\n" +
                "pMBUsUubXdJGCW93NzwP0zBwj7vOIo6NAvLvn4i2BBgBCAAgFiEElKaRM98EX0DQ\n" +
                "aAUzhqgNkN6Elr0FAl8HbrwCGwwACgkQhqgNkN6Elr1bjwP/W2JtCRwnxNgVdcbU\n" +
                "3zfVlCwljUR1CWju5BmcF9bYfwoTILfTgCAVwFGxjsqrrvJEJk50yv750j7K7doY\n" +
                "w1mEeQD8sq3a7LtAYB0J5JUVZPZrhhhLr/aEzEApxbHe87az3YRS18+CbmAxaXQM\n" +
                "/KklwXlLbh1XsdundPIfbD8x9L4=\n" +
                "=8LWa\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        String publicKeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "mI0EXwduvAEEAMSlxoJS2h+P8cwZqtsxKeKgGXZ9v7OHkI9iy4JwQUkw6kSTiRPP\n" +
                "yQuE4ly1S67BJ0DNOqVwo+eeVJeXsRlH3ZOvZE2X6NUxqe1Zo6TLVALC3a2YXzeo\n" +
                "Lgfrb/Q1SjzPQhOOQHK4UBbqYXmK9riLMzF3c38PKX+n+WyNQEbBzsQdABEBAAG0\n" +
                "GGFsZnJlc2NvLWVuY3J5cHRpb24tdGVzdIjOBBMBCAA4FiEElKaRM98EX0DQaAUz\n" +
                "hqgNkN6Elr0FAl8HbrwCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQhqgN\n" +
                "kN6Elr1uVQP+MZbWfX2ci2Rvw+NjW3Ug3qr4Snh7qc9G7Ynty5LlelDlGFqvBOvq\n" +
                "up8HmXH7NzbkC8z/kqhuvdnZjD0xRgeh/PDWtymEVl48OYEqU+A9w369iiT+XFn9\n" +
                "YOxxpEPxplH4USKrfwYpY6JaZGuZ3mDmgifFri9jGqMVeMHfuXgEABm4jQRfB268\n" +
                "AQQAwraHRGnN74r/OqT/dyvr/cXq5Bifkzhulr8ZHdmeTMPacihNniILyzOFCbuZ\n" +
                "cnN8Auu2Wc0E0rmi3K4fMH0qtESpDQJUNmPG59xRwiO6StNwnuBQGJpuhesDbXjB\n" +
                "lhFDzltazoC8NBEQKzDi/HTCiaWRaST5ztSBLCXsD4vt9GcAEQEAAYi2BBgBCAAg\n" +
                "FiEElKaRM98EX0DQaAUzhqgNkN6Elr0FAl8HbrwCGwwACgkQhqgNkN6Elr1bjwP/\n" +
                "W2JtCRwnxNgVdcbU3zfVlCwljUR1CWju5BmcF9bYfwoTILfTgCAVwFGxjsqrrvJE\n" +
                "Jk50yv750j7K7doYw1mEeQD8sq3a7LtAYB0J5JUVZPZrhhhLr/aEzEApxbHe87az\n" +
                "3YRS18+CbmAxaXQM/KklwXlLbh1XsdundPIfbD8x9L4=\n" +
                "=PtJh\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        InputStream encryptedMessage = new ByteArrayInputStream(encryptedString.getBytes());
        InputStream privateKey = new ByteArrayInputStream(privateKeyString.getBytes());
        InputStream publicKey = new ByteArrayInputStream(publicKeyString.getBytes());

        InputStream decryptedMessage = gpgEncryptionUtil.decryptFile(encryptedMessage, privateKey, publicKey, "password".toCharArray());

        String decryptedString = new BufferedReader(new InputStreamReader(decryptedMessage))
                .lines()
                .collect(Collectors.joining("\n"));

        assertEquals("this is the file", decryptedString);
    }

    @Test
    public void canEncryptFile() throws IOException, PGPException, SignatureException {
        String contents = "this is a file";

        String privateKeyString = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "lQIGBF8HbrwBBADEpcaCUtofj/HMGarbMSnioBl2fb+zh5CPYsuCcEFJMOpEk4kT\n" +
                "z8kLhOJctUuuwSdAzTqlcKPnnlSXl7EZR92Tr2RNl+jVMantWaOky1QCwt2tmF83\n" +
                "qC4H62/0NUo8z0ITjkByuFAW6mF5iva4izMxd3N/Dyl/p/lsjUBGwc7EHQARAQAB\n" +
                "/gcDAvrbkUDGjgfL6G16S8eGcUKmtLc0gMnjwthyJdBGmRMPc0TtjrGDgmL24CFV\n" +
                "jFcp65Kcogsxluoost6tRYOXtSkqWJbVkbzTxGTNE+odJO0/PMrD8mwgmsLWCl2+\n" +
                "eDZ58hexVW45KFrhxDFphRv4/uTZEQAc8S9x+ryRdBcFDYf71FRD4GjxMgG+cny3\n" +
                "sKKlcUCL1WtuptUbkZ5H6pUZ6pYVoEMb3a3bqDBUS8Ygm3t7F4Y/xM8WXNkB0HlN\n" +
                "/KwEOvuSSAI8sXhFwfb4RM+33npvKTEPVegijI3tH4PxxV42Je+TBWgIpOGDYNgi\n" +
                "gnBh4AvVhum+FGwiMn8bo2nEHcKwaGjapSIbzmsefa+dU6qX3RygrPm6g4y3BNtP\n" +
                "eXfb3KyrjVZJvK2J09oa8hT0lOzxpxaN47ShIvafc8qLUZjCRbrSUmC0ZgKRUvs3\n" +
                "iKrhU3NyW//Rdtfl4yPcINqYYnm2CzqalFQHD+DAIuKMIj2VPGCPvJq0GGFsZnJl\n" +
                "c2NvLWVuY3J5cHRpb24tdGVzdIjOBBMBCAA4FiEElKaRM98EX0DQaAUzhqgNkN6E\n" +
                "lr0FAl8HbrwCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQhqgNkN6Elr1u\n" +
                "VQP+MZbWfX2ci2Rvw+NjW3Ug3qr4Snh7qc9G7Ynty5LlelDlGFqvBOvqup8HmXH7\n" +
                "NzbkC8z/kqhuvdnZjD0xRgeh/PDWtymEVl48OYEqU+A9w369iiT+XFn9YOxxpEPx\n" +
                "plH4USKrfwYpY6JaZGuZ3mDmgifFri9jGqMVeMHfuXgEABmdAgYEXwduvAEEAMK2\n" +
                "h0Rpze+K/zqk/3cr6/3F6uQYn5M4bpa/GR3ZnkzD2nIoTZ4iC8szhQm7mXJzfALr\n" +
                "tlnNBNK5otyuHzB9KrREqQ0CVDZjxufcUcIjukrTcJ7gUBiaboXrA214wZYRQ85b\n" +
                "Ws6AvDQRECsw4vx0womlkWkk+c7UgSwl7A+L7fRnABEBAAH+BwMCb/3ERMpjk8To\n" +
                "vO3wMZskGc4eziCkgA2SQmx6m2mO5MPuMPkoYfMbOEXzek6bhzYluUtbOu74MFMk\n" +
                "1rRED0W+fe0wBuT2dXfpfWNBfY1CcLDh1uO8sCgd4bdApkqORj7BX/IxK0ljdMA3\n" +
                "ZF0tKAvw8A3FVj3zAEgRU5/iSZCd1AT1OdjPgtRIG7/khKayLUYIqH8K6WuaL+AH\n" +
                "0y5n9ZsXiRsmVF8N4huRNhNxCy3oadY+YxiOzxmBWFVZayM26gGpth6CzGPpAosb\n" +
                "hDlg4NWa7QSkO1Krn0cdQAYZWO8rmLRI5YucWcpJZ4IJ7NBfNvy0IGjPBEnDhHX9\n" +
                "mHBWio/eokFL2AWzR/fX39E4q/QgzQZOYVXaFS50WDmHOENHV+/XOtBuriAuhZ6s\n" +
                "FQu96o25bCDGV9MP3CT4l6ql3Keo5iUOLzD7F/2/CPAhTl8ZFGuJY5JvLhkk3B70\n" +
                "pMBUsUubXdJGCW93NzwP0zBwj7vOIo6NAvLvn4i2BBgBCAAgFiEElKaRM98EX0DQ\n" +
                "aAUzhqgNkN6Elr0FAl8HbrwCGwwACgkQhqgNkN6Elr1bjwP/W2JtCRwnxNgVdcbU\n" +
                "3zfVlCwljUR1CWju5BmcF9bYfwoTILfTgCAVwFGxjsqrrvJEJk50yv750j7K7doY\n" +
                "w1mEeQD8sq3a7LtAYB0J5JUVZPZrhhhLr/aEzEApxbHe87az3YRS18+CbmAxaXQM\n" +
                "/KklwXlLbh1XsdundPIfbD8x9L4=\n" +
                "=8LWa\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        String publicKeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "mI0EXwduvAEEAMSlxoJS2h+P8cwZqtsxKeKgGXZ9v7OHkI9iy4JwQUkw6kSTiRPP\n" +
                "yQuE4ly1S67BJ0DNOqVwo+eeVJeXsRlH3ZOvZE2X6NUxqe1Zo6TLVALC3a2YXzeo\n" +
                "Lgfrb/Q1SjzPQhOOQHK4UBbqYXmK9riLMzF3c38PKX+n+WyNQEbBzsQdABEBAAG0\n" +
                "GGFsZnJlc2NvLWVuY3J5cHRpb24tdGVzdIjOBBMBCAA4FiEElKaRM98EX0DQaAUz\n" +
                "hqgNkN6Elr0FAl8HbrwCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQhqgN\n" +
                "kN6Elr1uVQP+MZbWfX2ci2Rvw+NjW3Ug3qr4Snh7qc9G7Ynty5LlelDlGFqvBOvq\n" +
                "up8HmXH7NzbkC8z/kqhuvdnZjD0xRgeh/PDWtymEVl48OYEqU+A9w369iiT+XFn9\n" +
                "YOxxpEPxplH4USKrfwYpY6JaZGuZ3mDmgifFri9jGqMVeMHfuXgEABm4jQRfB268\n" +
                "AQQAwraHRGnN74r/OqT/dyvr/cXq5Bifkzhulr8ZHdmeTMPacihNniILyzOFCbuZ\n" +
                "cnN8Auu2Wc0E0rmi3K4fMH0qtESpDQJUNmPG59xRwiO6StNwnuBQGJpuhesDbXjB\n" +
                "lhFDzltazoC8NBEQKzDi/HTCiaWRaST5ztSBLCXsD4vt9GcAEQEAAYi2BBgBCAAg\n" +
                "FiEElKaRM98EX0DQaAUzhqgNkN6Elr0FAl8HbrwCGwwACgkQhqgNkN6Elr1bjwP/\n" +
                "W2JtCRwnxNgVdcbU3zfVlCwljUR1CWju5BmcF9bYfwoTILfTgCAVwFGxjsqrrvJE\n" +
                "Jk50yv750j7K7doYw1mEeQD8sq3a7LtAYB0J5JUVZPZrhhhLr/aEzEApxbHe87az\n" +
                "3YRS18+CbmAxaXQM/KklwXlLbh1XsdundPIfbD8x9L4=\n" +
                "=PtJh\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        InputStream originalMessage = new ByteArrayInputStream(contents.getBytes());
        InputStream privateKey = new ByteArrayInputStream(privateKeyString.getBytes());
        InputStream publicKey = new ByteArrayInputStream(publicKeyString.getBytes());

        try (ByteArrayOutputStream encryptedOutStream = new ByteArrayOutputStream()) {
            gpgEncryptionUtil.encryptFile(originalMessage, encryptedOutStream, publicKey);

            InputStream decryptedMessage = gpgEncryptionUtil.decryptFile(new ByteArrayInputStream(encryptedOutStream.toByteArray()), privateKey, publicKey, "password".toCharArray());

            String decryptedString = new BufferedReader(new InputStreamReader(decryptedMessage))
                    .lines()
                    .collect(Collectors.joining("\n"));

            assertEquals(contents, decryptedString);
        }
    }
}
