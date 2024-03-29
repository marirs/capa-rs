use crate::{error::Error, Result};
use core::{marker::PhantomPinned, pin::Pin, ptr};
use memmap2::{Mmap, MmapOptions};
use std::{fs, path::Path};

pub(crate) struct BinaryParser {
    bytes: Mmap,
    object: Option<goblin::Object<'static>>,
    _pin: PhantomPinned,
}

impl BinaryParser {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Pin<Box<Self>>> {
        let file = fs::File::open(&path).map_err(Error::IoError)?;

        let bytes = unsafe { MmapOptions::new().map(&file) }.map_err(Error::IoError)?;

        let mut result = Box::pin(Self {
            bytes,
            object: None,
            _pin: PhantomPinned,
        });

        // SAFETY:
        // `result` is now allocated, initialized and pinned on the heap.
        // Its location is therefore stable, and we can store references to it
        // in other places.
        //
        // Construct a reference to `result.bytes` that lives for the 'static
        // life time:
        //     &ref => pointer => 'static ref
        //
        // This is safe because the `Drop` implementation drops `Self::object`
        // before `Self::bytes`.
        let bytes_ref: &'static Mmap =
            unsafe { ptr::NonNull::from(&result.bytes).as_ptr().as_ref().unwrap() };

        let object = goblin::Object::parse(bytes_ref).map_err(Error::ParseError)?;

        result.as_mut().set_object(Some(object));
        Ok(result)
    }

    pub(crate) fn object(&self) -> &goblin::Object {
        // SAFETY: All instances of `Self` that are created and still in scope
        // must have `Some(_)` in the `object` field.
        self.object.as_ref().unwrap()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn set_object(mut self: Pin<&mut Self>, object: Option<goblin::Object<'static>>) {
        let this = Pin::as_mut(&mut self);

        // SAFETY: Storing to the field `object` does not move `this`.
        unsafe { Pin::get_unchecked_mut(this) }.object = object;
    }

    fn drop_pinned(self: Pin<&mut Self>) {
        // SAFETY: Drop `object` before `bytes` is dropped.
        self.set_object(None);
    }
}

impl Drop for BinaryParser {
    fn drop(&mut self) {
        // SAFETY: All instances of `Self` are pinned.
        unsafe { Pin::new_unchecked(self) }.drop_pinned();
    }
}
