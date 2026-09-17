//! Ordered multi-child split trees, following canonical MultiplexerState.
use crate::state::Rect;

#[derive(Clone)]
pub enum Layout {
    Pane(u32),
    Split {
        horizontal: bool,
        children: Vec<Layout>,
        sizes: Vec<f32>,
    },
}

impl Layout {
    /// Canonical dumpNode uses the first/last *pane* rectangles, including
    /// zoomed/stale rectangles, rather than recomputing split geometry.
    pub fn dump(&self, rect: &impl Fn(u32) -> Rect) -> String {
        match self {
            Self::Pane(id) => {
                let r = rect(*id);
                format!("{}x{},{},{},{id}", r.cols, r.rows, r.x, r.y)
            }
            Self::Split {
                horizontal,
                children,
                ..
            } => {
                let panes = self.panes();
                let first = rect(panes[0]);
                let last = rect(*panes.last().unwrap());
                let (cols, rows) = if *horizontal {
                    (
                        i32::from(last.x) + i32::from(last.cols) - i32::from(first.x),
                        i32::from(first.rows),
                    )
                } else {
                    (
                        i32::from(first.cols),
                        i32::from(last.y) + i32::from(last.rows) - i32::from(first.y),
                    )
                };
                let body = children
                    .iter()
                    .map(|child| child.dump(rect))
                    .collect::<Vec<_>>()
                    .join(",");
                let (open, close) = if *horizontal { ('{', '}') } else { ('[', ']') };
                format!("{cols}x{rows},{},{}{open}{body}{close}", first.x, first.y)
            }
        }
    }
    pub fn panes(&self) -> Vec<u32> {
        match self {
            Self::Pane(p) => vec![*p],
            Self::Split { children, .. } => children.iter().flat_map(Self::panes).collect(),
        }
    }
    pub fn contains(&self, pane: u32) -> bool {
        match self {
            Self::Pane(p) => *p == pane,
            Self::Split { children, .. } => children.iter().any(|c| c.contains(pane)),
        }
    }
    /// Creation appends to an existing same-axis parent; move inserts beside
    /// its destination. In both cases all previous weights are halved.
    pub fn insert(&mut self, dest: u32, pane: u32, horizontal: bool, before: Option<bool>) {
        match self {
            Self::Pane(p) if *p == dest => {
                let children = if before == Some(true) {
                    vec![Self::Pane(pane), Self::Pane(dest)]
                } else {
                    vec![Self::Pane(dest), Self::Pane(pane)]
                };
                *self = Self::Split {
                    horizontal,
                    children,
                    sizes: vec![0.5, 0.5],
                };
            }
            Self::Split {
                horizontal: axis,
                children,
                sizes,
            } => {
                if *axis == horizontal {
                    if let Some(index) = children
                        .iter()
                        .position(|c| matches!(c, Self::Pane(p) if *p == dest))
                    {
                        let at = before.map_or(children.len(), |b| index + usize::from(!b));
                        for size in sizes.iter_mut() {
                            *size *= 0.5;
                        }
                        children.insert(at, Self::Pane(pane));
                        sizes.insert(at, 0.5);
                        return;
                    }
                }
                if let Some(child) = children.iter_mut().find(|c| c.contains(dest)) {
                    child.insert(dest, pane, horizontal, before);
                }
            }
            _ => {}
        }
    }
    pub fn remove(self, pane: u32) -> Option<Self> {
        match self {
            Self::Pane(p) => (p != pane).then_some(Self::Pane(p)),
            Self::Split {
                horizontal,
                children,
                sizes,
            } => {
                let (mut children, mut sizes): (Vec<_>, Vec<_>) = children
                    .into_iter()
                    .zip(sizes)
                    .filter_map(|(c, s)| c.remove(pane).map(|c| (c, s)))
                    .unzip();
                match children.len() {
                    0 => None,
                    1 => children.pop(),
                    _ => {
                        let sum: f32 = sizes.iter().sum();
                        for size in &mut sizes {
                            *size /= sum;
                        }
                        Some(Self::Split {
                            horizontal,
                            children,
                            sizes,
                        })
                    }
                }
            }
        }
    }
    pub fn swap(&mut self, a: u32, b: u32) {
        match self {
            Self::Pane(p) => {
                if *p == a {
                    *p = b;
                } else if *p == b {
                    *p = a;
                }
            }
            Self::Split { children, .. } => {
                for child in children {
                    child.swap(a, b);
                }
            }
        }
    }
    fn rects(horizontal: bool, sizes: &[f32], rect: Rect) -> Vec<Rect> {
        let total = if horizontal { rect.cols } else { rect.rows };
        let available = total
            .saturating_sub(sizes.len() as u16 - 1)
            .max(sizes.len() as u16);
        let mut used: u16 = 0;
        sizes
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let size = if i + 1 == sizes.len() {
                    available.saturating_sub(used).max(1)
                } else {
                    (s * f32::from(available)).round().max(1.0) as u16
                };
                let mut child = rect;
                if horizontal {
                    child.cols = size;
                    child.x += used + i as u16;
                } else {
                    child.rows = size;
                    child.y += used + i as u16;
                }
                used += size;
                child
            })
            .collect()
    }
    pub fn geometry(&self, rect: Rect, panes: &mut Vec<(u32, Rect)>) -> String {
        let prefix = format!("{}x{},{},{}", rect.cols, rect.rows, rect.x, rect.y);
        match self {
            Self::Pane(p) => {
                panes.push((*p, rect));
                format!("{prefix},{p}")
            }
            Self::Split {
                horizontal,
                children,
                sizes,
            } => {
                let body = children
                    .iter()
                    .zip(Self::rects(*horizontal, sizes, rect))
                    .map(|(c, r)| c.geometry(r, panes))
                    .collect::<Vec<_>>()
                    .join(",");
                let (open, close) = if *horizontal { ('{', '}') } else { ('[', ']') };
                format!("{prefix}{open}{body}{close}")
            }
        }
    }
    /// None means no ancestor controls this axis; Some(false) is a no-op.
    pub fn absolute(
        &mut self,
        pane: u32,
        axis: bool,
        want: u16,
        rect: &impl Fn(u32) -> Rect,
    ) -> Option<bool> {
        let Self::Split {
            horizontal,
            children,
            sizes,
        } = self
        else {
            return None;
        };
        let index = children.iter().position(|c| c.contains(pane))?;
        if let Some(changed) = children[index].absolute(pane, axis, want, rect) {
            return Some(changed);
        }
        if *horizontal != axis {
            return None;
        }
        let mut dims: Vec<i32> = children
            .iter()
            .map(|child| {
                let panes = child.panes();
                let first = rect(panes[0]);
                let last = rect(*panes.last().unwrap());
                if axis {
                    (i32::from(last.x) + i32::from(last.cols) - i32::from(first.x)).max(1)
                } else {
                    (i32::from(last.y) + i32::from(last.rows) - i32::from(first.y)).max(1)
                }
            })
            .collect();
        let total: i32 = dims.iter().sum();
        let target = i32::from(want).clamp(1, total - dims.len() as i32 + 1);
        let delta = target - dims[index];
        if delta == 0 {
            return Some(false);
        }
        if delta > 0 {
            let mut need = delta;
            for j in (index + 1..dims.len()).chain((0..index).rev()) {
                let take = need.min(dims[j] - 1);
                dims[j] -= take;
                dims[index] += take;
                need -= take;
            }
        } else if delta < 0 {
            dims[index] = target;
            let neighbor = if index + 1 < dims.len() {
                index + 1
            } else {
                index - 1
            };
            dims[neighbor] -= delta;
        }
        for (size, dimension) in sizes.iter_mut().zip(dims) {
            *size = dimension as f32 / total as f32;
        }
        Some(true)
    }
    pub fn directional(
        &mut self,
        pane: u32,
        dir: char,
        amount: i32,
        rect: &impl Fn(u32) -> Rect,
    ) -> bool {
        let Self::Split {
            horizontal,
            children,
            sizes,
        } = self
        else {
            return false;
        };
        let Some(index) = children.iter().position(|c| c.contains(pane)) else {
            return false;
        };
        if !matches!(children[index], Self::Pane(_)) {
            return children[index].directional(pane, dir, amount, rect);
        }
        if *horizontal != matches!(dir, 'L' | 'R') {
            return false;
        }
        let backwards = matches!(dir, 'L' | 'U');
        let (neighbor, grow) = if backwards && index > 0 {
            (index - 1, true)
        } else if !backwards && index + 1 < children.len() {
            (index + 1, true)
        } else if index > 0 {
            (index - 1, false)
        } else {
            (index + 1, false)
        };
        // Canonical directional resize uses the first leaf's dimension, unlike
        // absolute resize which measures each entire child subtree.
        let mut dims: Vec<i32> = children
            .iter()
            .map(|child| {
                let first = rect(child.panes()[0]);
                i32::from(if *horizontal { first.cols } else { first.rows })
            })
            .collect();
        let total: i32 = dims.iter().sum();
        let shrinking = if grow { neighbor } else { index };
        let movement = amount.max(0).min(dims[shrinking] - 1);
        if movement == 0 {
            return false;
        }
        let delta = if grow { movement } else { -movement };
        dims[index] += delta;
        dims[neighbor] -= delta;
        for (size, dimension) in sizes.iter_mut().zip(dims) {
            *size = dimension as f32 / total as f32;
        }
        movement != 0
    }
    pub fn select(&mut self, name: &str) {
        let ids = self.panes();
        if ids.len() < 2 {
            return;
        }
        let horizontal = matches!(name, "even-horizontal" | "main-vertical")
            || (!name.contains("vertical") && name != "main-horizontal");
        let sizes = vec![1.0 / ids.len() as f32; ids.len()];
        *self = Self::Split {
            horizontal,
            children: ids.into_iter().map(Self::Pane).collect(),
            sizes,
        };
    }
}
