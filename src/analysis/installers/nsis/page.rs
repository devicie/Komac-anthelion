use std::fmt;

use zerocopy::{FromBytes, I32, Immutable, KnownLayout, LE};

/// <https://github.com/NSIS-Dev/nsis/blob/v311/Source/exehead/fileform.h#L446>
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Page {
    dialog_id: I32<LE>,
    window_proc_id: I32<LE>,
    pre_function: I32<LE>,
    show_function: I32<LE>,
    leave_function: I32<LE>,
    rest: [u8],
}

impl Page {
    /// Returns the code offset of the function called before the page is created. For custom
    /// pages, this function creates and shows the page.
    #[inline]
    pub const fn pre_function(&self) -> i32 {
        self.pre_function.get()
    }

    /// Returns the code offset of the function called right before the page is shown.
    #[inline]
    pub const fn show_function(&self) -> i32 {
        self.show_function.get()
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("DialogId", &self.dialog_id)
            .field("WindowProcId", &self.window_proc_id)
            .field("PreFunction", &self.pre_function)
            .field("ShowFunction", &self.show_function)
            .field("LeaveFunction", &self.leave_function)
            .finish_non_exhaustive()
    }
}
