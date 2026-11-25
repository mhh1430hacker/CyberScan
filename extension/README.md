# CyberScan browser extension (Chrome and Edge, Manifest V3)

Check links and downloads before you open them.

- **Right-click a link > Scan link with CyberScan.** Right-click selected text or an empty part
  of a page to check that text or the page's own address.
- **Right-click a link to a file > Scan this download.**
- **Finished downloads:** each one gets instant checks of its address and file name. A risky one
  (double extension such as `invoice.pdf.exe`, hidden direction characters, a look-alike site,
  a program from a strange address) raises a notification with **Check on CyberScan** and
  **Show file**. In the popup you can choose to be told about every finished download.
- **Toolbar popup:** paste a link and see the instant result; **This page** fills in the current
  tab's address; **Full check on CyberScan** opens the scan page with the link filled in.
- **Badge** on the toolbar icon: `!` looks dangerous, `?` worth a closer look, `✓` no warning
  signs in the address.

## Privacy

- The instant checks (`heuristics.js`) read only the text of the address or file name, on your
  computer. No page is fetched and nothing is sent.
- The full check happens only when you click: the extension opens
  `https://scan.ainex-ai.xyz/#/scan?url=<link>`, the link is filled into the scan page, and you
  press **Start check** there. The extension never uploads files itself. To check a downloaded
  file, use **Show file** and drop it on the scan page.
- No remote code, no analytics, no account. Settings and the list of the last 15 downloads stay
  in `chrome.storage.local` on your computer.

Permissions and why they are needed:

| permission | why |
|---|---|
| `contextMenus` | the right-click items |
| `downloads` | to see when a download finishes (its address and file name) and to show the file in its folder |
| `notifications` | the warning when a risky download finishes |
| `storage` | the "notify for every download" setting and the recent downloads list |
| `activeTab` | the popup's **This page** button reads the current tab's address, only when you open the popup |

No host permissions are requested: the extension cannot read or change web pages.

## Install for testing (load unpacked)

1. Chrome: open `chrome://extensions`. Edge: open `edge://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose this `extension` folder.
4. Pin CyberScan from the puzzle-piece menu so the badge is visible.

Test: `node extension/test/heuristics.test.js` checks the instant hints (look-alike domains,
punycode, risky endings, double extensions, hidden characters).

## Package

From the project root (PowerShell):

```powershell
Compress-Archive -Force -Path extension\manifest.json, extension\background.js, extension\heuristics.js, extension\popup.*, extension\icons, extension\_locales -DestinationPath dist\CyberScan-extension-1.0.0.zip
```

The zip must have `manifest.json` at its root (it does with the command above). The `test`
folder and this README are left out. Raise `"version"` in `manifest.json` before every upload.

## Chrome Web Store

1. Register at <https://chrome.google.com/webstore/devconsole> (one-time USD 5 fee, Google account;
   two-step verification is required).
2. **New item** > upload `CyberScan-extension-1.0.0.zip`.
3. **Store listing:** name and description (from `docs/stores/extension-listing.md`), category
   *Tools* or *Productivity*, language English (add Arabic), the 128x128 icon
   (`icons/icon-128.png`), at least one screenshot of 1280x800 or 640x400, optional promo tile
   440x280.
4. **Privacy practices:** single purpose: "check links and downloads for warning signs before the
   user opens them". Justify each permission with the table above. Data use: the extension does
   not collect or transmit user data (tick none of the data types) and certify the three
   statements. Privacy policy URL: `https://ainex-ai.xyz/privacy` (or the site's privacy page).
   Remote code: **No**.
5. **Distribution:** public, all regions. Submit for review (usually a few days).

## Microsoft Edge Add-ons

1. Register at <https://partner.microsoft.com/dashboard/microsoftedge> (free; a Microsoft account).
2. **Create new extension** > upload the same zip (Edge accepts Chrome MV3 packages unchanged).
3. Availability: public, all markets. Properties: category *Productivity*, privacy policy URL,
   website `https://ainex-ai.xyz/`.
4. Store listing per language (English and Arabic): description, the 300x300 logo (make one from
   `web_v/static/icon-512.png`), at least one screenshot 1280x800 or 640x480.
5. Submit; certification usually takes up to 7 working days.
