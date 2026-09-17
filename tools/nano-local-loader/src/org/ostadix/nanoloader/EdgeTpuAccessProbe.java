package org.ostadix.nanoloader;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONObject;

/** Preserve stock service authorization errors without invoking any model API. */
public final class EdgeTpuAccessProbe {
    public static void main(String[] args) throws Exception {
        if (args.length > 1 || (args.length == 1 && !args[0].equals("get-fd"))) {
            throw new IllegalArgumentException("no arguments: query own UID authorization; get-fd: request/release device descriptor");
        }
        boolean getFd = args.length == 1;
        String descriptor = "com.google.edgetpu.IEdgeTpuAppService";
        IBinder service = (IBinder) Class.forName("android.os.ServiceManager")
            .getMethod("checkService", String.class).invoke(null, descriptor + "/default");
        JSONObject result = new JSONObject();
        result.put("schema", "ostadix.edgetpu-access-probe/v1");
        result.put("uid", Process.myUid());
        result.put("pid", Process.myPid());
        result.put("selinux_context", new String(Files.readAllBytes(Paths.get("/proc/self/attr/current")), StandardCharsets.UTF_8).trim());
        result.put("operation", getFd ? "getEdgeTpuFd" : "userIsAuthorized");
        result.put("inference_executed", false);
        if (service == null) {
            result.put("service_present", false);
            System.out.println(result.toString());
            System.exit(1);
        }
        result.put("service_present", true);
        result.put("interface_descriptor", service.getInterfaceDescriptor());
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(descriptor);
            if (!getFd) data.writeInt(Process.myUid());
            boolean handled = service.transact(getFd ? 1 : 7, data, reply, 0);
            result.put("transaction_handled", handled);
            if (!handled) throw new IllegalStateException("stock service rejected transaction code");
            reply.readException();
            result.put("success", true);
            if (getFd) {
                result.put("reply_contains_fd", reply.hasFileDescriptors());
                // No duplication or device use. Recycling closes the parcel-owned descriptor.
            } else {
                result.put("authorized", reply.readInt() != 0);
            }
        } catch (RuntimeException failure) {
            result.put("success", false);
            result.put("exception", failure.getClass().getName());
            result.put("message", failure.getMessage());
            if (failure.getClass().getName().equals("android.os.ServiceSpecificException")) {
                result.put("service_specific_error", failure.getClass().getField("errorCode").getInt(failure));
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
        System.out.println(result.toString());
        if (!result.optBoolean("success")) System.exit(1);
    }
}
