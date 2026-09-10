/*
 * Copyright 2023 Harness, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React from 'react'
import cx from 'classnames'
import { Container, FormInput, Text } from '@harnessio/uicore'
import type { FormikProps } from 'formik'
import { useStrings } from 'framework/strings'
import type { RulesFormPayload } from 'components/ProtectionRules/ProtectionRulesUtils'
import css from '../ProtectionRulesForm.module.scss'

const PushRulesForm = ({ formik }: { formik: FormikProps<RulesFormPayload> }) => {
  const { getString } = useStrings()
  const { setFieldValue } = formik
  const { limitFileSize } = formik.values

  return (
    <>
      <FormInput.CheckBox
        className={css.checkboxLabel}
        label={getString('protectionRules.limitFileSize')}
        name={'limitFileSize'}
        onChange={e => {
          if (!(e.target as HTMLInputElement).checked) {
            setFieldValue('fileSizeLimit', '')
          }
        }}
      />
      <Text padding={{ left: 'xlarge' }} className={css.checkboxText}>
        {getString('protectionRules.limitFileSizeText')}
      </Text>
      {limitFileSize && (
        <Container padding={{ left: 'xlarge', top: 'medium' }}>
          <FormInput.Text
            inputGroup={{ type: 'number' }}
            className={cx(css.widthContainer, css.minText)}
            name={'fileSizeLimit'}
            placeholder={getString('protectionRules.fileSizePlaceholder')}
          />
        </Container>
      )}

      <hr className={css.dividerContainer} />
      <FormInput.CheckBox
        className={css.checkboxLabel}
        label={getString('protectionRules.principalCommitterMatch')}
        name={'principalCommitterMatch'}
      />
      <Text padding={{ left: 'xlarge' }} className={css.checkboxText}>
        {getString('protectionRules.principalCommitterMatchText')}
      </Text>

      <hr className={css.dividerContainer} />
      <FormInput.CheckBox
        className={css.checkboxLabel}
        label={getString('protectionRules.secretScanningEnabled')}
        name={'secretScanningEnabled'}
      />
      <Text padding={{ left: 'xlarge' }} className={css.checkboxText}>
        {getString('protectionRules.secretScanningEnabledText')}
      </Text>
    </>
  )
}

export default PushRulesForm
