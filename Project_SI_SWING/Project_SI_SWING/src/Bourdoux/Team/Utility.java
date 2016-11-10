package Bourdoux.Team;

/**
 * Created by fabio on 08-11-2016.
 */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Utility {

    public static byte[] objectToBytes(Object o) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(o);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Object bytesToObject(byte[] byteArray) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(byteArray);
             ObjectInputStream in = new ObjectInputStream(bis)) {
            return in.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}