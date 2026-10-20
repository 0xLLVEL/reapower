package rat.cosmetics;

import com.lunarclient.common.v1.Color;
import com.lunarclient.common.v1.Uuid;
import com.lunarclient.websocket.cosmetic.v2.EquippedCosmetic;
import com.lunarclient.websocket.cosmetic.v2.PlayerCosmeticsPushV2;
import net.fabricmc.api.ClientModInitializer;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RatCosmetics implements ClientModInitializer {

    private static final String LOCATOR =
        "com.moonsworth.lunar.client.util.RHCRCOORHOOCRRHRHCOHHICOHIIIHO";

    private static final Path GAME = Paths.get(
        System.getProperty("user.home"), ".lunarclient", "settings", "game");
    private static final Path IDS_FILE = GAME.resolve("rat-cosmetics.txt");
    private static final Path LOG_FILE = GAME.resolve("rat-cosmetics.log");
    private static final Path ACCOUNTS = GAME.resolve("accounts.json");

    private static final Pattern PROFILE_ID = Pattern.compile(
        "\"minecraftProfile\"\\s*:\\s*\\{\\s*\"id\"\\s*:\\s*\"([0-9a-fA-F]{32})\"");

    private static final int[] FALLBACK_IDS = { 3, 2424, 894 };

    private static final Set<String> seen = new HashSet<>();

    @Override
    public void onInitializeClient() {
        Thread t = new Thread(RatCosmetics::loop, "rat-cosmetics");
        t.setDaemon(true);
        t.start();
    }

    private static void loop() {
        for (;;) {
            try {
                Thread.sleep(3000L);
            } catch (InterruptedException e) {
                return;
            }
            try {
                inject();
            } catch (Throwable t) {
                log("ERR " + t);
            }
        }
    }

    private static void inject() throws Exception {
        int[] ids = readIds();
        if (ids.length == 0) {
            return;
        }
        UUID me = readUuid();
        if (me == null) {
            return;
        }

        Uuid pu = Uuid.newBuilder()
            .setHigh64(me.getMostSignificantBits())
            .setLow64(me.getLeastSignificantBits())
            .build();

        PlayerCosmeticsPushV2.Builder b = PlayerCosmeticsPushV2.newBuilder()
            .setPlayerUuid(pu)
            .setLogoColor(Color.newBuilder().setColor(0x55FFFF))
            .setPlusColor(Color.newBuilder().setColor(0x55FFFF))
            .setLogoAlwaysShow(true);
        for (int id : ids) {
            b.addDefaultCosmetics(EquippedCosmetic.newBuilder()
                .setCosmeticId(id)
                .setShowOverSkinLayer(true)
                .setShowOverHelmet(true));
        }
        PlayerCosmeticsPushV2 push = b.build();

        Object root = callStatic(LOCATOR, "IRHOCRROOOIICOOCRRRIRHICOHICOC", new Class<?>[0]);
        if (root == null) {
            log("NOTREADY root=null");
            return;
        }
        Object mgr  = call(root, "HHRCCCROHCRHHOCRHCCRRORRIOCCOO", new Class<?>[0]);
        Object disp = call(root, "IRHOHHIIHICCIOIIRCCCCCHHIOCCRC", new Class<?>[0]);
        if (mgr == null || disp == null) {
            log("NOTREADY mgr=" + (mgr != null) + " disp=" + (disp != null));
            return;
        }

        call(disp, "CORRIROORHRIRIHCRHROIOCRCCIOIH",
             new Class<?>[]{ PlayerCosmeticsPushV2.class }, push);
        call(mgr, "RRRRRIRCCIIORHHCCCHICOCRRCOOOH",
             new Class<?>[]{ UUID.class, PlayerCosmeticsPushV2.class, int.class },
             me, push, Integer.valueOf(0));

        log("OK ids=" + Arrays.toString(ids) + " uuid=" + me);
    }

    private static Object callStatic(String cls, String name, Class<?>[] sig, Object... args)
            throws Exception {
        return find(Class.forName(cls), name, sig).invoke(null, args);
    }

    private static Object call(Object target, String name, Class<?>[] sig, Object... args)
            throws Exception {
        return find(target.getClass(), name, sig).invoke(target, args);
    }

    private static Method find(Class<?> c, String name, Class<?>[] sig) throws Exception {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            try {
                return k.getMethod(name, sig);
            } catch (NoSuchMethodException ignored) {
                // keep walking
            }
            try {
                Method m = k.getDeclaredMethod(name, sig);
                m.setAccessible(true);
                return m;
            } catch (NoSuchMethodException ignored) {
                // keep walking
            }
        }
        throw new NoSuchMethodException(c.getName() + "." + name);
    }

    private static UUID readUuid() {
        try {
            String s = new String(Files.readAllBytes(ACCOUNTS), StandardCharsets.UTF_8);
            Matcher m = PROFILE_ID.matcher(s);
            if (!m.find()) {
                return null;
            }
            String h = m.group(1);
            return UUID.fromString(
                h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16)
                    + "-" + h.substring(16, 20) + "-" + h.substring(20, 32));
        } catch (Exception e) {
            return null;
        }
    }

    private static int[] readIds() {
        try {
            if (!Files.exists(IDS_FILE)) {
                StringBuilder sb = new StringBuilder();
                sb.append("# satu id kosmetik per baris. ambil dari cosmetics.json (field \"id\").\n");
                sb.append("# 3 = Lunar Client Classic cloak, 2424 = Sun Glasses Black, 894 = Blue Tie.\n");
                for (int id : FALLBACK_IDS) {
                    sb.append(id).append('\n');
                }
                Files.write(IDS_FILE, sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            List<Integer> out = new ArrayList<>();
            for (String line : Files.readAllLines(IDS_FILE, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                int cut = t.indexOf('#');
                if (cut >= 0) {
                    t = t.substring(0, cut).trim();
                }
                try {
                    out.add(Integer.valueOf(t));
                } catch (NumberFormatException ignored) {
                    // bukan angka, lewati
                }
            }
            int[] r = new int[out.size()];
            for (int i = 0; i < r.length; i++) {
                r[i] = out.get(i).intValue();
            }
            return r;
        } catch (Exception e) {
            return FALLBACK_IDS.clone();
        }
    }

    private static synchronized void log(String s) {
        if (!seen.add(s)) {
            return;
        }
        try {
            Files.write(LOG_FILE, (s + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // logging gagal bukan masalah
        }
    }
}
