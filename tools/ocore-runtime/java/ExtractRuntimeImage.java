/* Host-side inventory helper. It is not an O-core runtime realization. */
import java.io.IOException;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.net.URI;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.TreeSet;

class ExtractRuntimeImage {
    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: ExtractRuntimeImage.java OUTPUT MODULE...");
        }
        Path output = Path.of(args[0]).toAbsolutePath();
        if (Files.exists(output)) {
            try (var files = Files.list(output)) {
                if (files.findAny().isPresent()) {
                    throw new IllegalArgumentException("output directory must be empty: " + output);
                }
            }
        }
        Files.createDirectories(output);
        var finder = ModuleFinder.ofSystem();
        var pending = new ArrayDeque<String>();
        var selected = new TreeSet<String>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("--all")) {
                finder.findAll().forEach(ref -> pending.add(ref.descriptor().name()));
            } else {
                pending.add(args[i]);
            }
        }
        while (!pending.isEmpty()) {
            String name = pending.remove();
            if (!selected.add(name)) {
                continue;
            }
            ModuleDescriptor descriptor = finder.find(name)
                .orElseThrow(() -> new IllegalArgumentException("missing required module: " + name))
                .descriptor();
            // Retain all declared dependencies, including requires static when present.
            // A missing module is an explicit failure, never an automatic scope reduction.
            descriptor.requires().forEach(required -> pending.add(required.name()));
        }
        var image = FileSystems.getFileSystem(URI.create("jrt:/"));
        for (String name : selected) {
            Path root = image.getPath("/modules", name);
            try (var paths = Files.walk(root)) {
                for (Path source : paths.toList()) {
                    if (!Files.isRegularFile(source)) {
                        continue;
                    }
                    Path target = output.resolve(name).resolve(root.relativize(source).toString());
                    Files.createDirectories(target.getParent());
                    Files.copy(source, target, StandardCopyOption.COPY_ATTRIBUTES);
                }
            }
        }
        Files.writeString(output.resolve("modules.txt"), String.join("\n", selected) + "\n");
        Files.writeString(output.resolve("runtime.properties"),
            "java.home=" + System.getProperty("java.home") + "\n" +
            "java.runtime.version=" + System.getProperty("java.runtime.version") + "\n" +
            "java.vm.name=" + System.getProperty("java.vm.name") + "\n");
        System.out.println("extracted " + selected.size() + " modules: " + String.join(", ", selected));
    }
}
