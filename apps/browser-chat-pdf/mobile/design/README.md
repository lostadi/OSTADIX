# Chatprint Mobile design concepts

These concepts define the visual direction for the mobile installer and print
preview. The application implements the controls and document content in HTML,
CSS, and JavaScript.

## Installer

Reference: [installer-concept.png](installer-concept.png).

Use a white background, near-black text, cobalt `#155EEF` primary actions,
fine gray separators, and compact sans-serif controls. Keep the layout readable
in a portrait phone viewport around 390 by 844 pixels.

The primary action copies the bookmarklet. The setup instructions explain how
to save it as a bookmark, open a conversation, and run that bookmark from the
address bar. Show copy confirmation near the action and keep detailed Android
instructions available without crowding the main flow.

## Print preview

Reference: [preview-concept.png](preview-concept.png).

Present one centered paper surface on a light gray workspace. Use serif type
for document content and sans-serif type for controls. Preserve readable
message labels, paragraphs, lists, code blocks, tables, source metadata, and an
editable title.

Keep the return action near the title and the Print / Save PDF action accessible
on a phone. Include the Share to Print fallback where the browser cannot open a
print dialog. Document text must remain selectable.
