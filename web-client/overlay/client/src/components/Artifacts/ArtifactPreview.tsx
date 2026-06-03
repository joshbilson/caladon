import React, { memo, useMemo, useEffect, useRef, type MutableRefObject } from 'react';
import { SandpackPreview, SandpackProvider } from '@codesandbox/sandpack-react/unstyled';
import type {
  SandpackProviderProps,
  SandpackPreviewRef,
} from '@codesandbox/sandpack-react/unstyled';
import type { TStartupConfig } from 'librechat-data-provider';
import type { ArtifactFiles } from '~/common';
import { sharedFiles, buildSandpackOptions } from '~/utils/artifacts';

export const ArtifactPreview = memo(function ({
  files,
  fileKey,
  template,
  sharedProps,
  previewRef,
  currentCode,
  startupConfig,
}: {
  files: ArtifactFiles;
  fileKey: string;
  template: SandpackProviderProps['template'];
  sharedProps: Partial<SandpackProviderProps>;
  previewRef: MutableRefObject<SandpackPreviewRef>;
  currentCode?: string;
  startupConfig?: TStartupConfig;
}) {
  const artifactFiles = useMemo(() => {
    if (Object.keys(files).length === 0) {
      return files;
    }
    const code = currentCode ?? '';
    if (!code) {
      return files;
    }
    return {
      ...files,
      [fileKey]: { code },
    };
  }, [currentCode, files, fileKey]);

  const options: SandpackProviderProps['options'] = useMemo(
    () => buildSandpackOptions(template, startupConfig),
    [startupConfig, template],
  );

  /**
   * Caladon artifact lock-down (SURGERY.md §C1). Force the Sandpack preview iframe to
   * `sandbox="allow-scripts"` and CRITICALLY omit `allow-same-origin`: without it the frame runs
   * in an opaque origin, so untrusted model HTML cannot read cookies/localStorage/IndexedDB/the
   * parent DOM, and any fetch to our origin is cross-origin + credential-less. Sandpack exposes no
   * `sandbox` prop on SandpackPreview, so we patch the rendered iframe on mount + observe for
   * re-renders. NEVER allow `allow-same-origin` + `allow-scripts` together — that lets the frame
   * remove its own sandbox. (Belt to §C2's braces: a CSP `connect-src 'none'` is injected into the
   * artifact document in utils/artifacts.ts.)
   */
  const containerRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const root = containerRef.current;
    if (!root) {
      return;
    }
    const harden = () => {
      const iframe = root.querySelector('iframe');
      if (iframe && iframe.getAttribute('sandbox') !== 'allow-scripts') {
        iframe.setAttribute('sandbox', 'allow-scripts');
        iframe.removeAttribute('allow');
      }
    };
    harden();
    const observer = new MutationObserver(harden);
    observer.observe(root, { childList: true, subtree: true, attributes: true });
    return () => observer.disconnect();
  }, [artifactFiles, fileKey]);

  if (Object.keys(artifactFiles).length === 0) {
    return null;
  }

  return (
    <div ref={containerRef} className="h-full w-full">
      <SandpackProvider
        files={{ ...artifactFiles, ...sharedFiles }}
        options={options}
        {...sharedProps}
        template={template}
      >
        <SandpackPreview
          showOpenInCodeSandbox={false}
          showRefreshButton={false}
          tabIndex={0}
          ref={previewRef}
        />
      </SandpackProvider>
    </div>
  );
});
