# Chatprint Mobile design concepts

Both concepts were generated with the built-in OpenAI ImageGen tool and then
used as visual references for the code-native installer and preview UI.

## Installer concept

Output: `installer-concept.png`

Prompt:

> Use case: ui-mockup. Create a polished, complete portrait mobile web installer screen for Chatprint, using the attached Chatprint popup only as the visual-system reference. Purpose: help an Android Chrome or Brave user install a self-contained bookmarklet that turns the current AI chat live DOM into a selectable PDF preview. Native phone viewport around 390x844, true white background, near-black text, cobalt #155EEF primary action, fine cool-gray rules, restrained 7/10 product-design polish, generous but efficient spacing, sans-serif UI typography, document-outline brand mark. Exact visible copy, rendered clearly and verbatim: brand “Chatprint”; headline “Print AI chats from your phone”; body “No extension required. Add Chatprint as a bookmark, open a conversation, then run it from your address bar.”; a prominent cobalt button “Copy bookmarklet”; success state helper “Copied — now save it as a bookmark”; section heading “Set it up in 3 steps”; numbered open-layout instructions “1 Copy the bookmarklet”, “2 Create or edit a bookmark and paste it into the URL field”, “3 Open your AI chat, type Chatprint in the address bar, and select the bookmark”; a subtle link “Show detailed Android steps”; footer “Runs locally • Nothing uploaded”. Include a small code-native-looking bookmark preview row labeled “Chatprint — Print this chat” with a URL field beginning “javascript:”. Use open layout and horizontal rules, not a card grid. No hero eyebrow, badges, fake metrics, gradients, illustrations, photos, extra navigation, or unrelated claims. All controls/text are code-native in the eventual implementation; this is a readable production design spec.

## Preview concept

Output: `preview-concept.png`

Prompt:

> Use case: ui-mockup. Create a polished, complete portrait mobile Chatprint print-preview screen at roughly 390x844, using the attached desktop preview and mobile installer as strict visual-system references. Purpose: after an Android bookmarklet captures the live AI-chat DOM, show a readable semantic preview whose text remains selectable and which can be handed to Android Print/Save as PDF. True white paper, very light cool-gray workspace, near-black typography, cobalt #155EEF primary action, fine gray rules, serif document typography and sans-serif controls, restrained shadows and compact mobile spacing. Exact code-native visible copy: top bar brand “Chatprint” and text button “Back to chat”; editable title “Planning a resilient garden”; small metadata “chat.example.com” and “September 4, 2026”; message labels “You” and “Assistant”; sample readable paragraphs; assistant heading “A practical starting point”; a short bulleted list; a three-line monospace code block; a compact two-column table with headings “Task” and “Why it helps”; fixed bottom cobalt button “Print / Save PDF”; small helper “If the print dialog does not open, use Share → Print.” Show the full interaction surface and enough document content to prove formatting, while keeping text legible. Use open layout and one centered paper surface, not a card grid. No badges, hero eyebrow, fake metrics, gradients, photos, decorative illustrations, extra navigation, or unrelated controls.
