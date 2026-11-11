package io.github.mhh1430hacker.cyberscan;

import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Quick Settings tile: "Check copied link" opens CyberScan and pastes the link from the clipboard. */
public class CheckLinkTileService extends TileService {
    @Override
    public void onStartListening() {
        Tile tile = getQsTile();
        if (tile == null) return;
        tile.setState(Tile.STATE_INACTIVE);
        tile.updateTile();
    }

    @Override
    @SuppressLint("StartActivityAndCollapseDeprecated") // the Intent form only runs below Android 14
    @SuppressWarnings("deprecation")
    public void onClick() {
        Intent open = new Intent(this, MainActivity.class)
            .setAction(MainActivity.ACTION_LINK)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        if (Build.VERSION.SDK_INT >= 34) {
            PendingIntent pi = PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            startActivityAndCollapse(pi);
        } else {
            startActivityAndCollapse(open);
        }
    }
}
