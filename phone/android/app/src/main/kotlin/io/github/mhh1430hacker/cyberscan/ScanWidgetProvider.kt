package io.github.mhh1430hacker.cyberscan

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.widget.RemoteViews

/**
 * Home-screen widget: the latest check (verdict, what was checked, score, when) and a
 * "Quick scan" button that opens CyberScan's file picker. The app writes the latest result
 * through MainActivity's "updateWidget" call; the widget never reads files itself.
 */
class ScanWidgetProvider : AppWidgetProvider() {
    companion object {
        private const val PREFS = "cyberscan_widget"

        fun save(ctx: Context, verdict: String, label: String, target: String, score: Int, whenText: String, button: String, empty: String) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("verdict", verdict).putString("label", label).putString("target", target)
                .putInt("score", score).putString("when", whenText).putString("button", button).putString("empty", empty)
                .apply()
            val mgr = AppWidgetManager.getInstance(ctx)
            val ids = mgr.getAppWidgetIds(ComponentName(ctx, ScanWidgetProvider::class.java))
            for (id in ids) render(ctx, mgr, id)
        }

        fun render(ctx: Context, mgr: AppWidgetManager, id: Int) {
            val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val views = RemoteViews(ctx.packageName, R.layout.cyberscan_widget)
            val verdict = p.getString("verdict", "") ?: ""
            if (verdict.isEmpty()) {
                views.setTextViewText(R.id.widget_verdict, "CyberScan")
                views.setTextColor(R.id.widget_verdict, Color.parseColor("#22E8FF"))
                views.setTextViewText(R.id.widget_target, p.getString("empty", null)?.ifEmpty { null } ?: "No checks yet")
                views.setTextViewText(R.id.widget_meta, "")
            } else {
                val color = when (verdict) { "clear" -> "#3DFFB0"; "review" -> "#FFC84A"; else -> "#FF4F6D" }
                views.setTextViewText(R.id.widget_verdict, p.getString("label", verdict))
                views.setTextColor(R.id.widget_verdict, Color.parseColor(color))
                views.setTextViewText(R.id.widget_target, p.getString("target", ""))
                views.setTextViewText(R.id.widget_meta, "${p.getInt("score", 0)}/100 · ${p.getString("when", "")}")
            }
            views.setTextViewText(R.id.widget_button, p.getString("button", "Quick scan"))

            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            val open = Intent(ctx, MainActivity::class.java).setAction(Intent.ACTION_MAIN)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            views.setOnClickPendingIntent(R.id.widget_root, PendingIntent.getActivity(ctx, 1, open, flags))
            val quick = Intent(ctx, MainActivity::class.java).setAction(MainActivity.ACTION_QUICK_SCAN)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            views.setOnClickPendingIntent(R.id.widget_button, PendingIntent.getActivity(ctx, 2, quick, flags))
            mgr.updateAppWidget(id, views)
        }
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        for (id in appWidgetIds) render(context, appWidgetManager, id)
    }
}
